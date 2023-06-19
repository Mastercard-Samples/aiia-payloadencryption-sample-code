using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Security.KeyVault.Keys;

const string algorithm = "RSA-OAEP-256";
const string encryption = "A256GCM";
const string contentType = "application/json";

var baseUrl = new Uri("https://api.nordicapigateway.com/");

// Credentials obtained from creating an Enterprise app in https://portal.aiia.eu/
var clientId = "<your-client-id>";
var clientSecret = "<your-client-secret>";

using var httpClient = new HttpClient { BaseAddress = baseUrl };

// Create a new RSA key pair for the client.
// Here we generate the key pair every time we execute the program,
// but it is encouraged to generate the keys once and reuse them over a period of time
using var clientRsaKeyPair = RSA.Create(2048);

var serverPublicKey = await GetServerPublicKey(httpClient);

var requestBody = JsonSerializer.Serialize(new
{
    userHash = $"{Guid.NewGuid()}",
    redirectUrl = "https://example.com"
});

// Sample request to the initialize endpoint, see docs for more information: https://api.nordicapigateway.com/docs
var initializeRequest = new HttpRequestMessage(HttpMethod.Post, "/v1/authentication/initialize");
var encryptedRequestPayload = EncryptRequestPayload(serverPublicKey, requestBody);
initializeRequest.Content = new StringContent(encryptedRequestPayload, Encoding.UTF8, contentType);
initializeRequest.Headers.Add("X-Client-Id", clientId);
initializeRequest.Headers.Add("X-Client-Secret", clientSecret);

var clientPublicKey = new JsonWebKey(clientRsaKeyPair);

var b64ClientJwk = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
{
    kid = Guid.NewGuid().ToString(),
    kty = clientPublicKey.KeyType.ToString(),
    e = clientPublicKey.E,
    n = clientPublicKey.N,
})));
initializeRequest.Headers.Add("X-Payload-Encryption", $"clientPublicKey={b64ClientJwk}");

Console.WriteLine("UNENCRYPTED REQUEST:\n" + requestBody);
Console.WriteLine();
Console.WriteLine("ENCRYPTED REQUEST");
Console.WriteLine("--Header--");
Console.WriteLine("X-Payload-Encryption: " + $"clientPublicKey={b64ClientJwk}");
Console.WriteLine("--Body--");
Console.WriteLine(JsonNode.Parse(encryptedRequestPayload));


var initializeResponse = await httpClient.SendAsync(initializeRequest);
initializeResponse.EnsureSuccessStatusCode();
var initializeResponseContent = await initializeResponse.Content.ReadAsStringAsync();

Console.WriteLine("ENCRYPTED RESPONSE");
Console.WriteLine(JsonNode.Parse(initializeResponseContent));
var responseDecrypted = JsonNode.Parse(DecryptResponsePayload(clientRsaKeyPair, initializeResponseContent));

Console.WriteLine("DECRYPTED RESPONSE");
Console.WriteLine(responseDecrypted);
Debug.Assert(!string.IsNullOrWhiteSpace(responseDecrypted["authUrl"].GetValue<string>()));



async Task<JsonWebKey> GetServerPublicKey(HttpClient client)
{
    var serverKeyRequest = new HttpRequestMessage(HttpMethod.Get, "/v1/payload-encryption-key");
    var serverKeyResponse = await client.SendAsync(serverKeyRequest);
    serverKeyResponse.EnsureSuccessStatusCode();

    var serverKeyResponseContent = await serverKeyResponse.Content.ReadAsStringAsync();
    var serverKeyResponseContentParsed = JsonNode.Parse(serverKeyResponseContent);
    return JsonSerializer.Deserialize<JsonWebKey>(serverKeyResponseContentParsed["serverPublicKey"].ToJsonString());
}

string EncryptRequestPayload(JsonWebKey jsonWebKey, string requestPayload)
{
    var encryptedValue = EncryptToJwe(jsonWebKey, requestPayload);

    return JsonSerializer.Serialize(new { encryptedValue });
}

string DecryptResponsePayload(RSA privateKey, string responsePayload)
{
    var parsed = JsonNode.Parse(responsePayload);
    var encryptedResponse = parsed["encryptedValue"]!.GetValue<string>();

    return DecryptFromJwe(privateKey, encryptedResponse);
}

string EncryptToJwe(JsonWebKey jsonWebKey, string plaintextPayload)
{
    var serverRsa = jsonWebKey.ToRSA();
    
    var contentEncryptionKey = GenerateContentEncryptionKey(256);
    var encryptedKey = serverRsa.Encrypt(contentEncryptionKey, RSAEncryptionPadding.OaepSHA256);

    var iv = GenerateIv();
    var payloadBytes = Encoding.UTF8.GetBytes(plaintextPayload);
    var base64EncodedHeader = Base64UrlEncode(CreateJweHeader(jsonWebKey.Id));
    var (ciphertext, authTag) = AesEncrypt(contentEncryptionKey, iv, payloadBytes, Encoding.UTF8.GetBytes(base64EncodedHeader));

    // Package into a JWE payload
    return string.Join('.',
        base64EncodedHeader,
        Base64UrlEncode(encryptedKey),
        Base64UrlEncode(iv),
        Base64UrlEncode(ciphertext),
        Base64UrlEncode(authTag));
}

string DecryptFromJwe(RSA rsa, string jwePayload)
{
    // Parse the JWE payload
    var fields = jwePayload.Trim().Split('.');
    var rawHeader = Encoding.UTF8.GetBytes(fields[0]);
    var encryptedKey = Base64UrlDecode(fields[1]);
    var iv = Base64UrlDecode(fields[2]);
    var cipherText = Base64UrlDecode(fields[3]);
    var authTag = Base64UrlDecode(fields[4]);

    var contentEncryptionKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
    var plaintext = AesDecrypt(contentEncryptionKey, iv, authTag, cipherText, rawHeader);

    return Encoding.UTF8.GetString(plaintext);
}

static (byte[] Ciphertext, byte[] AuthTag) AesEncrypt(byte[] secretKeyBytes, byte[] nonce, byte[] plaintext,
    byte[] associatedData)
{
    var ciphertext = new byte[plaintext.Length];
    var authTag = new byte[AesGcm.TagByteSizes.MaxSize];
    using var aes = new AesGcm(secretKeyBytes);

    aes.Encrypt(nonce, plaintext, ciphertext, authTag, associatedData);

    return (ciphertext, authTag);
}


static byte[] AesDecrypt(byte[] secretKeyBytes, byte[] nonce, byte[] authTag, byte[] ciphertext, byte[] associatedData)
{
    using var aes = new AesGcm(secretKeyBytes);
    var plainText = new byte[ciphertext.Length];

    aes.Decrypt(nonce, ciphertext, authTag, plainText, associatedData);

    return plainText;
}

static byte[] CreateJweHeader(string fingerprint)
{
    var header = new
    {
        alg = algorithm,
        enc = encryption,
        kid = fingerprint,
        cty = contentType
    };

    return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
}

// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
static string Base64UrlEncode(byte[] arg)
{
    var s = Convert.ToBase64String(arg); // Regular base64 encoder
    s = s.Split('=')[0]; // Remove any trailing '='s
    s = s.Replace('+', '-'); // 62nd char of encoding
    s = s.Replace('/', '_'); // 63rd char of encoding
    return s;
}

// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
static byte[] Base64UrlDecode(string arg)
{
    var s = arg;
    s = s.Replace('-', '+'); // 62nd char of encoding
    s = s.Replace('_', '/'); // 63rd char of encoding
    switch (s.Length % 4) // Pad with trailing '='s
    {
        case 0: break; // No pad chars in this case
        case 2:
            s += "==";
            break; // Two pad chars
        case 3:
            s += "=";
            break; // One pad char
        default:
            throw new Exception(
                "Illegal base64url string!");
    }

    return Convert.FromBase64String(s); // Standard base64 decoder
}

static byte[] GenerateContentEncryptionKey(int bitLength)
{
    var cekMaterial = new byte[ByteCount(bitLength)];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(cekMaterial);
    return cekMaterial;
}

static byte[] GenerateIv()
{
    var iv = new byte[12]; // 96 bits as per NIST recommendation
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(iv);
    return iv;
}

static int ByteCount(int bitCount)
{
    var byteCount = bitCount / 8;
    return bitCount % 8 == 0
        ? byteCount
        : byteCount + 1;
}