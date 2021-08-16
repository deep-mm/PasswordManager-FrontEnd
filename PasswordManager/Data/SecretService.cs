using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace PasswordManager.Data
{
    [Authorize]
    public class SecretService
    {
        Helper helper { get; }
        public string apiUrl = "";
        public SecretService(IConfiguration configuration)
        {
            helper = new Helper(configuration);
            apiUrl = configuration["apiUrl"];
        }

        public async Task<Secret[]> GetSecrets(string masterKey)
        {
            try
            {
                HttpClient httpClient = new HttpClient();
                httpClient = await helper.SetTokenAsync(httpClient);

                var response = await httpClient.GetAsync($"{apiUrl}secret?code=" + masterKey);

                var stringData = await response.Content.ReadAsStringAsync();

                IEnumerable<Secret> data = JsonConvert.DeserializeObject<IEnumerable<Secret>>(stringData);
                foreach (Secret secret in data)
                {
                    secret.secretValue = await helper.DecryptSecret(secret.secretValue);
                }
                return data.ToArray();
            }
            catch (JsonSerializationException exception)
            {
                throw new JsonSerializationException("GetSecrets(): Error occured in Json Deserialization", exception);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception occured while getting secrets: " + e);
                throw new Exception("GetSecrets(): Exception occured while getting secrets", e);
            }
        }

        public async Task<bool> AddSecret(Secret secret, string masterKey)
        {
            HttpClient httpClient = new HttpClient();
            httpClient = await helper.SetTokenAsync(httpClient);

            secret.secretValue = await helper.EncryptSecret(secret.secretValue);

            var myContent = JsonConvert.SerializeObject(secret);
            var buffer = System.Text.Encoding.UTF8.GetBytes(myContent);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await httpClient.PostAsync($"{apiUrl}secret?code=" + masterKey, byteContent);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Add Secret failed: {response.StatusCode}");
            }
            return true;
        }

        public async Task<bool> UpdateSecret(Secret secret, string masterKey)
        {
            HttpClient httpClient = new HttpClient();
            httpClient = await helper.SetTokenAsync(httpClient);

            secret.secretValue = await helper.EncryptSecret(secret.secretValue);

            var myContent = JsonConvert.SerializeObject(secret);
            var buffer = System.Text.Encoding.UTF8.GetBytes(myContent);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await httpClient.PutAsync($"{apiUrl}secret/" + secret.secretName + "?code=" + masterKey, byteContent);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Update Secret failed: {response.StatusCode}");
            }
            return true;
        }

        public async Task<bool> DeleteSecret(Secret secret, string masterKey)
        {
            HttpClient httpClient = new HttpClient();
            httpClient = await helper.SetTokenAsync(httpClient);

            var myContent = JsonConvert.SerializeObject(secret);
            var buffer = System.Text.Encoding.UTF8.GetBytes(myContent);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await httpClient.DeleteAsync($"{apiUrl}secret/" + secret.secretName + "?code=" + masterKey);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Delete Secret failed: {response.StatusCode}");
            }
            return true;
        }
    }
}
