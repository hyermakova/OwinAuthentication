using Microsoft.AspNet.Identity;
using System.Threading.Tasks;

namespace SecurityCore.Services
{
    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            System.Diagnostics.Debug.WriteLine(message.Body);

            return Task.FromResult(0);
        }
    }
}
