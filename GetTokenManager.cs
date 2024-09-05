using Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection.Metadata;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;
using System.Net.Http.Headers;

namespace keyguardsample
{
    internal class GetTokenManager
    {
        public  static async Task<string> GetToken(string slcResponse, X509Certificate2 cert)
        {
            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert), "A valid X509 certificate must be provided for mTLS.");
            }

            // parse slcResponse to get required info
            var jsonResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(slcResponse);
            // get ests required info from SLC response
            jsonResponse.TryGetValue("client_id", out var clientId);
            jsonResponse.TryGetValue("credential", out var credential);
            jsonResponse.TryGetValue("regional_token_url", out var regional_token_url);
            jsonResponse.TryGetValue("tenant_id", out var tenant_id);
            
            Console.WriteLine($"Certificate Subject: {cert.Subject}");

            //Create an HttpClientHandler and configure it to use the client certificate
            HttpClientHandler handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual
            };

            handler.ClientCertificates.Add(cert);
            if (handler.ClientCertificates.Contains(cert))
            {
                Console.WriteLine("Cert added to HTTP client successfully.");
            }
            else
            {
                Console.WriteLine("Cert failed to add to HTTP client successfully.");
            }

            // attach the cert handler to http Client
            var httpClient = new HttpClient(handler);

            Console.WriteLine("Getting token from eSTS..........");

            var requestHeader = new Dictionary<string, string>
            {
                { "Content-Type", "application/x-www-form-urlencoded" },
                { "x-client-sku", "MSI.IMDS.PF" },
                { "x-client-ver", "123456" },
                { "xms-client-vminfo", "Foo" }
            };
            // TODO: need to check if all the required fields are presented in the response &resource=https://vault.azure.net/
            string body = $"grant_type=client_credentials&client_id={clientId}&scope=https://vault.azure.net/.default&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={credential}";

            // Create the request content
            var content = new StringContent(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");
            Console.WriteLine($"request url: {regional_token_url}/{tenant_id}/oauth2/v2.0/token");
            //var response = await client.SendAsync(request);
            string url = $"{regional_token_url}/{tenant_id}/oauth2/v2.0/token";
            var res2 = httpClient.PostAsync(url, content).Result;

            try
            {
                // Send the POST request synchronously
                var response = httpClient.PostAsync(url, content).Result;

                // Ensure the request was successful
                //response.EnsureSuccessStatusCode();

                // Read and output the response body
                var responseBody = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine(responseBody);
                return responseBody;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return "";
            }
        }
    }
}
