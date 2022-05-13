import axios from "axios";
import * as https from "https";
import * as fs from "fs";
import * as path from "path";
const ciphers = [
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
];
export const agent = new https.Agent({
  ciphers: ciphers.join(":"),
  honorCipherOrder: true,
  minVersion: "TLSv1.2",
});
export async function credentialsAuth(username: string, password: string) {
  // Stolen from https://github.com/ev3nvy/valorant-reauth-script/blob/f79a5efd3ecd7757bafa7f63a1d9ca579bd1bc58/index.js :>
  if (!process.env.VAL_PASSWORD || !process.env.VAL_USERNAME)
    return console.log("No valorant auth username or password");

  const parseUrl = (uri) => {
    let url = new URL(uri);
    let params = new URLSearchParams(url.hash.substring(1));
    let access_token = params.get("access_token");
    let id_token = params.get("id_token");
    let expires_in = parseInt(params.get("expires_in"));

    return { access_token, id_token, expires_in };
  };

  const cookie = (
    await axios.post(
      "https://auth.riotgames.com/api/v1/authorization",
      {
        client_id: "play-valorant-web-prod",
        nonce: 1,
        redirect_uri: "https://playvalorant.com/opt_in",
        response_type: "token id_token",
        scope: "account openid",
      },
      {
        headers: {
          "User-Agent":
            "RiotClient/43.0.1.4195386.4190634 rso-auth (Windows; 10;;Professional, x64)",
        },
        httpsAgent: agent,
      }
    )
  ).headers["set-cookie"].find((elem) => /^asid/.test(elem));
  const access_tokens = await axios.put(
    "https://auth.riotgames.com/api/v1/authorization",
    {
      type: "auth",
      username: username,
      password: password,
    },
    {
      headers: {
        Cookie: cookie,
        "User-Agent":
          "RiotClient/43.0.1.4195386.4190634 rso-auth (Windows; 10;;Professional, x64)",
      },
      httpsAgent: agent,
    }
  );
  access_tokens.data.error ? console.log(access_tokens.data.error) : console;
  var tokens: any = await parseUrl(access_tokens.data.response.parameters.uri);
  tokens.token = (
    await axios.post(
      "https://entitlements.auth.riotgames.com/api/token/v1",
      {},
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
      }
    )
  ).data.entitlements_token;
  tokens.subject = JSON.parse(
    Buffer.from(tokens.access_token.split(".")[1], "base64").toString()
  ).sub;
  return tokens;
}

export async function lockfileAuth() {
  let version = (await axios.get("https://valorant-api.com/v1/version")).data
    .data.riotClientVersion;
  async function axiosGet(url: string, headers: any, entitlements: any) {
    if (headers === "JWT") {
      var res = await axios.get(url, {
        headers: {
          "X-Riot-Entitlements-JWT": entitlements.token,
          "X-Riot-ClientVersion": version,
          "X-Riot-ClientPlatform":
            "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
          Authorization: "Bearer " + entitlements.accessToken,
        },
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
      });
    } else {
      var res = await axios.get(url, {
        headers: headers,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
      });
    }
    return res.data;
  }

  const contents = await fs.promises.readFile(
    path.join(
      process.env.LOCALAPPDATA!,
      "Riot Games\\Riot Client\\Config\\lockfile"
    ),
    "utf8"
  );
  let lD: any = {};
  [lD.name, lD.pid, lD.port, lD.password, lD.protocol] = contents.split(":");
  let entitlements = await axiosGet(
    `https://127.0.0.1:${lD.port}/entitlements/v1/token`,
    {
      Authorization:
        "Basic " +
        Buffer.from(`riot:${lD.password}`, "utf8").toString("base64"),
      "X-Riot-ClientVersion": version,
    },
    null
  ).catch(function (err) {
    console.log("Couldn't connect to lockfile");
  });
  entitlements.access_token = entitlements.accessToken;
  return entitlements;
}
