using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace PasswordManager.Data
{
    public class Helper
    {
        public IConfiguration Configuration { get; }
        public static AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
        public static KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
        public static string encryptionKeyUri = "";

        public Helper(IConfiguration configuration)
        {
            Configuration = configuration;
            encryptionKeyUri = configuration["keyvaultEncryptionKeyUri"];
        }
        
        public async Task<HttpClient> SetTokenAsync(HttpClient httpClient)
        {
            try
            {
                string authority = $"{Configuration["AzureAd:Instance"]}{Configuration["AzureAd:TenantId"]}";
                string clientId = Configuration["AzureAd:ClientId"];
                string clientSecret = Configuration["AzureAd:ClientSecret"];
                string resourceId = Configuration["AzureAd:ResourceId"];

                var authContext = new AuthenticationContext(authority);

                var credential = new ClientCredential(clientId, clientSecret);
                var authResult = await authContext.AcquireTokenAsync(resourceId, credential);
                var token = authResult.AccessToken;

                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return httpClient;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to set access token as header. Exception: " + e);
                throw new Exception("Failed to set access token as header. Exception: " + e);
            }
        }

        public async Task<string> DecryptSecret (string encryptedSecret)
        {
            try
            {
                string decryptedValue = System.Text.Encoding.UTF8.GetString(keyVaultClient.DecryptAsync(encryptionKeyUri, JsonWebKeyEncryptionAlgorithm.RSAOAEP, System.Text.Encoding.UTF8.GetBytes(encryptedSecret)).GetAwaiter().GetResult().Result);
                return decryptedValue;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to Decrypt Secret. Exception Occured: " + e);
                throw new Exception("Failed to Decrypt Secret. Exception Occured: " + e);
            }
        }

        public async Task<string> EncryptSecret(string decryptedSecret)
        {
            try
            {
                string encryptedValue = System.Text.Encoding.UTF8.GetString(keyVaultClient.EncryptAsync(encryptionKeyUri, JsonWebKeyEncryptionAlgorithm.RSAOAEP, System.Text.Encoding.UTF8.GetBytes(decryptedSecret)).GetAwaiter().GetResult().Result);
                return encryptedValue;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to Encrypt Secret. Exception Occured: " + e);
                throw new Exception("Failed to Encrypt Secret. Exception Occured: " + e);
            }
        }
    }
}
