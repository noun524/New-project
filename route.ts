import { NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import webpush from "web-push";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

const schema = z.object({
  full_name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(200),
  phone: z.string().trim().max(40).optional(),
  reason: z.string().trim().max(1000).optional(),
});

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ message: "Please sign in before requesting a card." }, { status: 401 });

    const form = await request.formData();
    const cardType = String(form.get("card_type") || "");
    const parsed = schema.safeParse({
      full_name: form.get("full_name"),
      email: form.get("email"),
      phone: form.get("phone") || "",
      reason: form.get("reason") || "",
    });
    const consent = form.get("consent") === "yes";
    if (!parsed.success || !["royal", "gold"].includes(cardType) || !consent) {
      return NextResponse.json({ message: "Please complete the required fields and consent." }, { status: 400 });
    }
    if (parsed.data.email.toLowerCase() !== (user.email || "").toLowerCase()) {
      return NextResponse.json({ message: "Use the same email address as your signed-in account." }, { status: 400 });
    }

    if (cardType === "gold") {
      const password = String(form.get("gold_password") || "");
      const hash = process.env.GOLD_CARD_PASSWORD_HASH;
      if (!hash || password.length < 8 || !(await bcrypt.compare(password, hash))) {
        return NextResponse.json({ message: "Gold Card password is incorrect or not configured." }, { status: 403 });
      }
    }

    const admin = createAdminClient();
    const { data: existing, error: lookupError } = await admin.from("card_requests")
      .select("id,status").eq("user_id", user.id).eq("card_type", cardType)
      .in("status", ["pending", "approved"]).maybeSingle();
    if (lookupError) throw lookupError;
    if (existing) return NextResponse.json({ message: `You already have a ${existing.status} ${cardType} card request.` }, { status: 409 });

    const { error } = await admin.from("card_requests").insert({
      card_type: cardType,
      user_id: user.id,
      full_name: parsed.data.full_name,
      email: parsed.data.email,
      phone: parsed.data.phone || null,
      reason: parsed.data.reason || null,
      status: "pending",
    });
    if (error) throw error;

    await admin.from("admin_notifications").insert({
      kind: "card_request",
      title: `New ${cardType} card request`,
      body: `${parsed.data.full_name} (${parsed.data.email}) requested access.`,
    });

    // Push is best-effort; the request remains saved even if push is not configured.
    await sendAdminPush(admin, cardType, parsed.data.full_name);
    return NextResponse.json({ message: "Your request is pending. The administrator will review it." });
  } catch (error) {
    console.error("Card request error:", error);
    return NextResponse.json({ message: "Could not submit the request. Please try again later." }, { status: 500 });
  }
}

async function sendAdminPush(admin: ReturnType<typeof createAdminClient>, cardType: string, applicant: string) {
  const publicKey = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT;
  if (!publicKey || !privateKey || !subject) return;

  try {
    webpush.setVapidDetails(subject, publicKey, privateKey);
    const { data: subscriptions } = await admin.from("push_subscriptions").select("id,subscription");
    await Promise.all((subscriptions || []).map(async (row) => {
      try {
        await webpush.sendNotification(row.subscription, JSON.stringify({
          title: `New ${cardType === "royal" ? "Royal" : "Gold"} Card request`,
          body: `${applicant} submitted an access request.`,
          url: "/admin#cards",
        }));
      } catch (error: unknown) {
        const statusCode = (error as { statusCode?: number })?.statusCode;
        if (statusCode === 404 || statusCode === 410) await admin.from("push_subscriptions").delete().eq("id", row.id);
      }
    }));
  } catch (error) {
    console.error("Admin push notification failed:", error);
  }
}
