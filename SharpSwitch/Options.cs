using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpSwitch
{
    internal class Options
    {
        [Option('d', "domain", Required = false)]
        public string Domain { get; set; }

        [Option('u', "username", Required = false)]
        public string Username { get; set; }

        [Option('p', "password", Required = false)]
        public string Password { get; set; }

        [Option('c', "cmd", Required = false)]
        public string Cmd { get; set; }

        [Option('h', "help", Required = false)]
        public bool Help { get; set; }

        // ASCII Art: https://patorjk.com/software/taag/#p=display&f=Big&t=ParsingTest
        public static void Usage()
        {
            string Usage = @"
   _____ _                      _____         _ _       _     
  / ____| |                    / ____|       (_) |     | |    
 | (___ | |__   __ _ _ __ _ __| (_____      ___| |_ ___| |__  
  \___ \| '_ \ / _` | '__| '_ \\___ \ \ /\ / / | __/ __| '_ \ 
  ____) | | | | (_| | |  | |_) |___) \ V  V /| | || (__| | | |
 |_____/|_| |_|\__,_|_|  | .__/_____/ \_/\_/ |_|\__\___|_| |_|
                         | |                                  
                         |_|                                               

                    Author: @pwnlog
                    Version: 0.0.1


Usage:
    SharpSwitch --domain <domain name> --username <username> --password <password> --cmd <command>

    
Options:
    -d, --domain         Domain name (optional)
    -u, --username       Domain user name
    -p, --password       Domain user password
    -c, --cmd            Launch cmd.exe or powershell.exe
    -h, --help           Display help menu
    

Important:
    Only use single quotes (' ') when there are special characters
    If there aren't any special characters don't use single quotes (' '), instead use double quotes


Examples:
    SharpSwitch --domain <domain name> --username user01 --password 'p@$$w0rd' --cmd powershell.exe
    SharpSwitch --username test01 --password password --cmd cmd.exe
";
            Console.WriteLine(Usage);
        }
    }
}
