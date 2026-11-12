
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

export async function onRequestPost({ request, env }) {
  try {
    if (
      Number(request.headers.get("content-length") || 0) > 1024
    ) {
      return new Response(null, { status: 413, headers });
    }

    const body = await request.text();

    if (body.length > 1024) {
      return new Response(null, { status: 413, headers });
    }

    const surname = normalize(JSON.parse(body).surname);

    if (
      !/^[α-ω]{3,60}$/.test(surname)
    ) {
      return Response.json(
        { error: "Μη έγκυρο επίθετο." },
        { status: 400, headers }
      );
    }

    if (!env.DB) {
      return Response.json(
        { error: "Η βάση δεν είναι διαθέσιμη." },
        { status: 503, headers }
      );
    }

    const matches = await env.DB.prepare(`
      SELECT DISTINCT group_id
      FROM guests
      WHERE search_surname = ?
        AND confirmed = 1
      LIMIT 5
    `).bind(surname).all();

    const groups = [];

    for (const match of matches.results) {
      const members = await env.DB.prepare(`
        SELECT full_name, table_number
        FROM guests
        WHERE group_id = ?
          AND confirmed = 1
        ORDER BY full_name
        LIMIT 20
      `).bind(match.group_id).all();

      groups.push({
        name: "Η παρέα σας",
        members: members.results
      });
    }

    return Response.json({ groups }, { headers });

  } catch {
    return Response.json(
      { error: "Η αναζήτηση απέτυχε." },
      { status: 400, headers }
    );
  }
}
