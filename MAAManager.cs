using System;
using System.Collections.Generic;

namespace keyguardsample
{
    // Mapping for IMDS region and MAA region

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


        public static async Task<string> GetMAAEndPoint()
        {
            string imdsInstanceEndpointLocation = "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-08-01&format=text";

            try
            {
                // Make the GET request
                string location = await FetchData(imdsInstanceEndpointLocation);
                Console.WriteLine($"Location: {location}");
                return MAARegionUrl(location.ToLower());
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Request error: {e.Message}");
                return "";
            }
        }

        static internal string MAARegionUrl(string imdsRegion)
        {
            return $"shared{IMDS_MAA_Map[imdsRegion]}.{IMDS_MAA_Map[imdsRegion]}.attest.azure.net";
        }
        static internal Dictionary<string, string> IMDS_MAA_Map = new Dictionary<string, string>
        {
            {"australiacentral", "cau"},
            {"australiacentral2", "cau2"},
            {"australiaeast", "eau"},
            {"australiasoutheast", "sau"},
            {"brazilsouth", "sbr"},
            {"canadacentral", "cac"},
            {"canadaeast", "cae"},
            {"centralindia", "cin"},
            {"centralus", "cus"},
            {"centraluseuap", "cuse"},
            {"eastasia", "easia"},
            {"eastus", "eus"},
            {"eastus2", "eus2"},
            {"eastus2euap", "eus2e"},
            {"eastusstg", "eus"},
            {"francecentral", "frc"},
            {"francesouth", "frs"},
            {"germanynorth", "den"},
            {"germanywestcentral", "dewc"},
            {"japaneast", "jpe"},
            {"japanwest", "jpw"},
            {"koreacentral", "krc"},
            {"koreasouth", "krs"},
            {"northcentralus", "ncus"},
            {"northeurope", "neu"},
            {"norwayeast", "noe"},
            {"norwaywest", "now"},
            {"southafricanorth", "san"},
            {"southafricawest", "saw"},
            {"southcentralus", "scus"},
            {"southcentralusstg", "scus"},
            {"southeastasia", "sasia"},
            {"southindia", "sin"},
            {"switzerlandnorth", "swn"},
            {"switzerlandwest", "sww"},
            {"uaecentral", "uaec"},
            {"uaenorth", "uaen"},
            {"uknorth", "uks"},
            {"uksouth", "uks"},
            {"uksouth2", "uks"},
            {"ukwest", "ukw"},
            {"westcentralus", "wcus"},
            {"westeurope", "weu"},
            {"westindia", "win"},
            {"westus", "wus"},
            {"westus2", "wus2"},
            {"usgovarizona", "uga"},
            {"usgovvirginia", "ugv"}
        };
    }
}
