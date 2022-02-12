using System;
using System.Reflection;

class Program
{
    public static void TestExport() // this functuion to exported
    {
        Assembly curAssembly = typeof(Program).Assembly;
        Console.WriteLine("The current executing assembly is {0}.", curAssembly);

        Module[] mods = curAssembly.GetModules();
        foreach (Module md in mods)
        {
            
            Console.WriteLine("This assembly contains the {0}", md.Name);
            Console.WriteLine("This assembly contains the fullQuiltfiDNAme {0}", md.FullyQualifiedName);
        }
    }

    static void Main(string[] args)
    {

        Console.WriteLine("Main");
        TestExport();
    }
}
