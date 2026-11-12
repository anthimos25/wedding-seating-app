
const normalize = (value) =>
  String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("el-GR")
    .replace(/ς/g, "σ")
    .trim();

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
};

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers
  });
}

async function verifyTurnstile(token, secret, ip) {
  if (
    typeof token !== "string" ||
    !token ||
    token.length > 2048 ||
    !secret
  ) {
    return false;
  }

  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);

  if (ip) {
    form.append("remoteip", ip);
  }

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(8000)
    }
  );

  if (!response.ok) {
    return false;
  }

  const result = await response.json();

  return result.success === true;
}

export async function onRequestPost({ request, env }) {
  try {
    if (
      Number(request.headers.get("content-length") || 0) >
      4096
    ) {
      return json(
        { error: "Το αίτημα είναι πολύ μεγάλο." },
        413
      );
    }

    const rawBody = await request.text();

    if (new TextEncoder().encode(rawBody).length > 4096) {
      return json(
        { error: "Το αίτημα είναι πολύ μεγάλο." },
        413
      );
    }

    let body;

    try {
      body = JSON.parse(rawBody);
    } catch {
      return json(
        { error: "Μη έγκυρο αίτημα." },
        400
      );
    }

    const surname = normalize(body?.surname);
    const token = body?.turnstileToken;

    if (!/^[α-ω]{3,60}$/.test(surname)) {
      return json(
        { error: "Πληκτρολογήστε ένα έγκυρο επίθετο." },
        400
      );
    }

    if (!env.TURNSTILE_SECRET_KEY || !env.DB) {
      return json(
        { error: "Η υπηρεσία δεν είναι διαθέσιμη." },
        503
      );
    }

    const ip =
      request.headers.get("CF-Connecting-IP") || "";

    const verified = await verifyTurnstile(
      token,
      env.TURNSTILE_SECRET_KEY,
      ip
    );

    if (!verified) {
      return json(
        { error: "Ο έλεγχος ασφαλείας απέτυχε." },
        403
      );
    }

    const matches = await env.DB.prepare(`
      SELECT DISTINCT group_id
      FROM guests
      WHERE search_surname = ?
        AND confirmed = 1
      LIMIT 5
    `)
      .bind(surname)
      .all();

    const groups = [];

    for (const match of matches.results || []) {
      const members = await env.DB.prepare(`
        SELECT full_name, table_number
        FROM guests
        WHERE group_id = ?
          AND confirmed = 1
        ORDER BY full_name
        LIMIT 20
      `)
        .bind(match.group_id)
        .all();

      groups.push({
        name: "Η παρέα σας",
        members: members.results || []
      });
    }

    return json({ groups });

  } catch (error) {
    console.error("Lookup error:", error);

    return json(
      {
        error: "Η αναζήτηση δεν είναι διαθέσιμη αυτή τη στιγμή."
      },
      500
    );
  }
}
