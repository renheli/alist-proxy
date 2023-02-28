// src/const.ts
var ADDRESS = "https://114.135.100.103:5244";
var TOKEN = "0.AXEAgksff7YgGUiLhgbiwOctav_VcrxTMApNoo6PfTjeT_CHAHs.AgABAAEAAAD--DLA3VO7QrddgJg7WevrAgDs_wUA9P-fb4IiJ0rTraZfNteq2uTmqow6r9l1y5H6y6xYZaGkwbA_U1k52CUEkU5wcxXUqfoPtNntOD_XwftCr-pQkpY4Hz6OQXuCRq6nC3qJpw4XWRnBR34l8VjK55OEWmwifC76eyjdrGS-IQJWEafbIMGS8o1i_I0zi8ocmdsvxqfSnss4v_tBWpBBJnLG9XKQDWHwnbXh8pW__yELm03tNgox2rXpnW_ad-PtN1K7_HCvOaK5JWxNDr8Fv-hh9n6kBl4QGam-8xXQN5olUKGNQ6yi8s4xghaCEEVgPBZu_fPxlXILH7Zd3l57Tfn4vxEj_2S9vm5HPZI9N9hOVEhxT37M_0TdSV6cgKKPi3sYGY1Dvq1SpsnzDQ4gFqn-7djXkUlq2mCXNLilVHG7OqyzdRFbfb6prLDBQ1D0f_WiV9-xio_EIaUCTQMtcXOO-gN2U7_iJWPRrH9-QcxXJq6W7oF3P6c7hLi2AAymIJNdnxsDQGIA5TEkMIGj5mH9EMiMycK9YOiGC5ZKsz2jxX8tSdtJ7Xa-DqWeincZP4BVKBRhWhGPriydTfR9bT6PxoI9ntBN5hy5bxKpgmLeEcGNrijBcl6r0jj61bfhw16ij4OKVtuBokE2DH9do6nD5sTVXOVE6l9cdKyGi2YOrYEH-PPl6a9Cccv_Z77PNpF42_V0Lk7jjL88et4THndzPtAt3S1qpH44_x410tJF07QefLHruwNtvUZEur5-wIPgSBpxlKJMq6QlGCe4uG2Caly1vRal8SuCc7VG4NP-EvdRvbuBUlL2-zAVWNmeFpzvR1wPpNjnkjeQHp84tfllqlRP3S8CL0NSWJQ96kv24QWWAmFOTG-SMEJrNVu3PR_o4siZM58vaGQPJOcEh6Pp_1Ve3Nu7EhV0j51PrQtvgDocL4X35O006KNI64uy76TQowRuc6tl";

// src/verify.ts
var verify = async (data, _sign) => {
  const signSlice = _sign.split(":");
  if (!signSlice[signSlice.length - 1]) {
    return "expire missing";
  }
  const expire = parseInt(signSlice[signSlice.length - 1]);
  if (isNaN(expire)) {
    return "expire invalid";
  }
  if (expire < Date.now() / 1e3 && expire > 0) {
    return "expire expired";
  }
  const right = await hmacSha256Sign(data, expire);
  if (_sign !== right) {
    return "sign mismatch";
  }
  return "";
};
var hmacSha256Sign = async (data, expire) => {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(TOKEN),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const buf = await crypto.subtle.sign(
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    key,
    new TextEncoder().encode(`${data}:${expire}`)
  );
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_") + ":" + expire;
};

// src/handleDownload.ts
async function handleDownload(request) {
  const origin = request.headers.get("origin") ?? "*";
  const url = new URL(request.url);
  const path = decodeURIComponent(url.pathname);
  const sign = url.searchParams.get("sign") ?? "";
  const verifyResult = await verify(path, sign);
  if (verifyResult !== "") {
    const resp2 = new Response(
      JSON.stringify({
        code: 401,
        message: verifyResult
      }),
      {
        headers: {
          "content-type": "application/json;charset=UTF-8"
        }
      }
    );
    resp2.headers.set("Access-Control-Allow-Origin", origin);
    return resp2;
  }
  let resp = await fetch(`${ADDRESS}/api/fs/link`, {
    method: "POST",
    headers: {
      "content-type": "application/json;charset=UTF-8",
      Authorization: TOKEN
    },
    body: JSON.stringify({
      path
    })
  });
  let res = await resp.json();
  if (res.code !== 200) {
    return new Response(JSON.stringify(res));
  }
  request = new Request(res.data.url, request);
  if (res.data.header) {
    for (const k in res.data.header) {
      for (const v of res.data.header[k]) {
        request.headers.set(k, v);
      }
    }
  }
  let response = await fetch(request);
  response = new Response(response.body, response);
  response.headers.delete("set-cookie");
  response.headers.set("Access-Control-Allow-Origin", origin);
  response.headers.append("Vary", "Origin");
  return response;
}

// src/handleOptions.ts
function handleOptions(request) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Max-Age": "86400"
  };
  let headers = request.headers;
  if (headers.get("Origin") !== null && headers.get("Access-Control-Request-Method") !== null) {
    let respHeaders = {
      ...corsHeaders,
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || ""
    };
    return new Response(null, {
      headers: respHeaders
    });
  } else {
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS"
      }
    });
  }
}

// src/index.ts
var src_default = {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return handleOptions(request);
    }
    return handleDownload(request);
  }
};
export {
  src_default as default
};
//# sourceMappingURL=index.js.map
