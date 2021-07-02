using System;

namespace WSSecurityHeaderTests
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write($"Type the username: ");
            string username = Console.ReadLine();

            Console.Write($"Type the password: ");
            string password = Console.ReadLine();

            WSSecurityHeaderFactory.Model.SecurityHeader securityHeader = new WSSecurityHeaderFactory.Model.SecurityHeader(username, password);
            string xmlHeader = securityHeader.GetHeader();

            Console.WriteLine("SECURITY HEADER GENERATED: ");
            Console.WriteLine(xmlHeader);
            Console.WriteLine("");
            Console.WriteLine("Press ENTER to finish...");
            Console.ReadLine();
        }
    }
}
