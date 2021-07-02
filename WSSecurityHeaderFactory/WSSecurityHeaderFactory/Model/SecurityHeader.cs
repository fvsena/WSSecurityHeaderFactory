using System;

namespace WSSecurityHeaderFactory.Model
{
    public class SecurityHeader
    {
        public string Nonce { get; set; }
        public string Created { get; set; }
        public string Expires { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Timeticks { get; set; }
        public string PasswordDigest { get; set; }

        public SecurityHeader(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

        /// <summary>
        /// Populates the internal properties with their specific values based on WS-Security protocol
        /// </summary>
        public void ComputeValues()
        {
            SecurityHeaderFactory securityHeader = new SecurityHeaderFactory();
            securityHeader.ComputeValues(Password, out string nonce, out string passwordDigest, out string created, out string expires, out string timeticks);

            Nonce = nonce;
            PasswordDigest = passwordDigest;
            Created = created;
            Expires = expires;
            Timeticks = timeticks;
        }

        /// <summary>
        /// Populates the internal properties with their specific values based on WS-Security protocol
        /// </summary>
        /// <returns>WS-Security header in string format</returns>
        public string GetHeader()
        {
            if (string.IsNullOrEmpty(Username))
            {
                throw new Exception("Username must be assigned before calculates the header");
            }

            if (string.IsNullOrEmpty(Password))
            {
                throw new Exception("Password must be assigned before calculates the header");
            }

            ComputeValues();

            string header = @"
                <wsse:Security xmlns:wsse=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"" xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
                      <wsu:Timestamp wsu:Id=""TS-70FF549EDA44462AC8" + Timeticks + @""">
                         <wsu:Created>" + Created + @"</wsu:Created>
                         <wsu:Expires>" + Expires + @"</wsu:Expires>
                      </wsu:Timestamp>
                      <wsse:UsernameToken wsu:Id=""UsernameToken-70FF549EDA44462AC8" + Timeticks + @""">
                         <wsse:Username>" + Username + @"</wsse:Username>
                         <wsse:Password Type=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"">" + PasswordDigest + @"</wsse:Password>
                         <wsse:Nonce EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"">" + Nonce + @"</wsse:Nonce>
                         <wsu:Created>" + Created + @"</wsu:Created>
                      </wsse:UsernameToken>
                   </wsse:Security>
            ";

            return header;
        }
    }
}
