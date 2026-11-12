
const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
};

const MAX_ATTEMPTS = 10;
const WINDOW_SECONDS = 60;

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      ...HEADERS,
      ...extraHeaders
    }
  });
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("el-GR")
    .replace(/ς/g, "σ")
    .trim();
}

async function hashIp(ip, secret) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(ip)
  );

  return Array.from(new Uint8Array(signature))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function checkRateLimit(db, ipHash) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart =
    Math.floor(now / WINDOW_SECONDS) * WINDOW_SECONDS;

  // Atomic increment: concurrent requests cannot
  // bypass the counter through a read-then-write race.
  const result = await db.prepare(`
    INSERT INTO lookup_limits (
      ip_hash,
      window_start,
      attempts
    )
    VALUES (?, ?, 1)
    ON CONFLICT(ip_hash, window_start)
    DO UPDATE SET attempts = attempts + 1
    RETURNING attempts
  `)
    .bind(ipHash, windowStart)
    .first();

  const attempts = Number(result?.attempts || 0);

  return {
    allowed: attempts <= MAX_ATTEMPTS,
    retryAfter: Math.max(
      1,
      windowStart + WINDOW_SECONDS - now
    )
  };
}

async function verifyTurnstile(token, secret, ip) {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > 2048
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

  return result.success === true &&
    result.hostname === "table-9ug.pages.dev";
}

export async function onRequestPost({ request, env }) {
  try {
    if (
      !env.DB ||
      !env.TURNSTILE_SECRET_KEY ||
      !env.IP_HASH_SECRET
    ) {
      return json(
        { error: "Η υπηρεσία δεν είναι διαθέσιμη." },
        503
      );
    }

    const ip = request.headers.get("CF-Connecting-IP");

    if (!ip) {
      return json(
        { error: "Δεν ήταν δυνατός ο έλεγχος ασφαλείας." },
        403
      );
    }

    const ipHash = await hashIp(
      ip,
      env.IP_HASH_SECRET
    );

    // Count attempts before expensive verification
    // and before querying guest data.
    const limit = await checkRateLimit(env.DB, ipHash);

    if (!limit.allowed) {
      return json(
        {
          error: "Πολλές αναζητήσεις. Δοκιμάστε ξανά αργότερα."
        },
        429,
        {
          "Retry-After": String(limit.retryAfter)
        }
      );
    }

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
