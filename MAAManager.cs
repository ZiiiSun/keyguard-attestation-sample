using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace keyguardsample
{
    internal class MAAManager
    {
        static async Task<string> FetchData(string endpoint)
        {
            // Create an instance of HttpClient
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Metadata", "true");

            try
            {
                var response = await client.GetAsync(endpoint);

                return await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException httpEx)
            {
                Console.WriteLine($"HTTP Request error: {httpEx.Message}");
                throw; 
            }
        }

        public static async Task GetRegionInfoFromIMDS()
        {
            string imdsInstanceEndpointLocation = "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-08-01&format=text";
            string imdsInstanceEndpointVmId = "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-08-01&format=text";

            try
            {
                // Make the GET request
                string location = await FetchData(imdsInstanceEndpointLocation);
                Console.WriteLine($"Location: {location}");
                string vmId = await FetchData(imdsInstanceEndpointVmId);
                Console.WriteLine($"vmId: {vmId}");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Request error: {e.Message}");
            }
        }
    }
}
