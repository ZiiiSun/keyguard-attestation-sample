using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace keyguardsample
{
    internal class ImdsManagedIdentityManager
    {
        private static readonly HttpClient client = new HttpClient();
        private static readonly Uri s_imdsEndpoint = new("http://169.254.169.254/metadata/identity/credential?cred-api-version=1.0");

        public async static Task GetMICredential(X509Certificate2 cert)
        {
            // Get the Base64-encoded certificate
            string base64Cert = Convert.ToBase64String(cert.GetRawCertData());

            // Prepare the x5c array (in this case, just one certificate)
            List<string> x5c = new List<string>
            {
                base64Cert
            };

            Console.WriteLine("Getting getting SLC...");
            var requestBody = new Dictionary<string, object>
            {
                {"cnf", new Dictionary<string, object>
                    {
                        { 
                            "jwk", new Dictionary<string, object>
                            {
                                    { "kty", "RSA" },
                                    { "use", "sig" },
                                    { "alg", "RS256" },
                                    { "kid", "bee56b9d-93db-4c16-abb7-2591e7d8d5cb" },
                                    { "x5c", x5c}
                            }
                        }
                    }
                },
                { "latch_key", false}
            };

            string jsonString = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, s_imdsEndpoint)
            {
                Content = content
            };

            request.Headers.Add("Metadata", "true");
            request.Headers.Add("x-ms-client-request-id", "12345678-1234-1234-1234-1234567890ab");
            request.Headers.Add("x-client-sku", "clientsku");
            request.Headers.Add("x-client-ver", "clientver");
            request.Headers.Add("x-client-os", "clientos");

            var response = await client.SendAsync(request);
            
            string responseBody = await response.Content.ReadAsStringAsync();
            // Handle the response
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"successfully got back MSI Credential!!!");
                Console.WriteLine(responseBody);
                Console.WriteLine($"-----------------------------------------------------------------");
                Console.WriteLine($"-----------------------------------------------------------------");
                Console.WriteLine($"-----------------------------------------------------------------");
                Console.WriteLine($"-----------------------------------------------------------------");
                string token = await GetTokenManager.GetToken(responseBody, cert);
            }
            else
            {
                Console.WriteLine($" body {jsonString}  /r Error: {response.StatusCode}, responseBody: {responseBody}");
            }

        }
    }
}
