using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ysonet.Helpers
{
    public static class LocalCodeCompiler
    {

        /// <summary>
        /// The provider version that emits CLR-v2 IL, so the assembly a payload CARRIES can be
        /// loaded by a .NET 2.0/3.0/3.5 target. "v3.5" is the newest CLR-v2 compiler and is what
        /// the in-box v3.5 csc.exe is; there is no separate "v2.0" provider worth using, because
        /// the 3.5 compiler still emits IL a 2.0 runtime loads.
        /// </summary>
        private const string Clr2CompilerVersion = "v3.5";

        public static byte[] GetAsmBytes(string fileChain)
        {
            return GetAsmBytes(fileChain, false);
        }

        /// <summary>
        /// <paramref name="targetClr2"/> compiles the source against the CLR-v2 compiler instead
        /// of the running one. It exists because an identity rewrite cannot reach INSIDE a
        /// compiled assembly: a chain that carries its own assembly as data is only as portable
        /// as the compiler that produced it, so a payload built here on 4.x is refused by a
        /// CLR-2 target no matter what the surrounding type names say. A DLL supplied directly
        /// is returned untouched, because the operator chose those bytes.
        /// </summary>
        public static byte[] GetAsmBytes(string fileChain, bool targetClr2)
        {
            if (fileChain.EndsWith(".dll") && !fileChain.Contains(".cs;"))
            {
                // we have a DLL file
                return GetAsmBytesFromDLL(fileChain);
            }
            else
            {
                // we need to compile the code
                return CompileToAsmBytes(fileChain, "", "", targetClr2);
            }
        }

        private static byte[] GetAsmBytesFromDLL(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new Exception("Assembly not found: " + filePath);
            }

            return File.ReadAllBytes(filePath);
        }

        public static byte[] CompileToAsmBytes(string fileChain, string compilerLanguage, string compilerOptions)
        {
            return CompileToAsmBytes(fileChain, compilerLanguage, compilerOptions, false);
        }

        public static byte[] CompileToAsmBytes(string fileChain, string compilerLanguage,
            string compilerOptions, bool targetClr2)
        {
            byte[] assemblyBytes = null;
            try
            {
                if (string.IsNullOrEmpty(compilerOptions))
                {
                    compilerOptions = "-t:library -o+ -platform:anycpu";
                }

                if (string.IsNullOrEmpty(compilerLanguage))
                {
                    compilerLanguage = "CSharp";
                }

                // The source is separated from its reference list with ';'. Within the
                // reference list accept both ',' (the documented FromFile command shape)
                // and additional ';' separators for compatibility with older commands.
                string[] commandParts = fileChain.Split(new[] { ';' }, 2);
                string sourceFile = commandParts[0].Trim();
                string[] references = commandParts.Length == 1
                    ? new string[0]
                    : commandParts[1].Split(new[] { ',', ';' },
                        StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .Where(s => s.Length > 0)
                        .ToArray();
                // The CLR-v2 provider is selected by the documented "CompilerVersion" provider
                // option, which is how System.CodeDom picks an older in-box csc.exe. Only C#
                // and VB expose it; refuse another language rather than emit a payload that
                // claims to target CLR 2 while carrying CLR-4 metadata.
                CodeDomProvider codeDomProvider;
                if (targetClr2)
                {
                    if (!string.Equals(compilerLanguage, "CSharp", StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(compilerLanguage, "VisualBasic", StringComparison.OrdinalIgnoreCase))
                        throw new NotSupportedException("The CLR-v2 compiler is supported only for C# and Visual Basic source.");
                    Dictionary<string, string> providerOptions = new Dictionary<string, string>();
                    providerOptions.Add("CompilerVersion", Clr2CompilerVersion);
                    codeDomProvider = CodeDomProvider.CreateProvider(compilerLanguage, providerOptions);
                }
                else
                {
                    codeDomProvider = CodeDomProvider.CreateProvider(compilerLanguage);
                }
                CompilerParameters compilerParameters = new CompilerParameters();
                compilerParameters.CompilerOptions = compilerOptions;
                compilerParameters.ReferencedAssemblies.AddRange(references);
                CompilerResults compilerResults = codeDomProvider.CompileAssemblyFromFile(
                    compilerParameters, sourceFile);
                if (compilerResults.Errors.Count > 0)
                {
                    var errorTexts = new List<string>();
                    foreach (CompilerError error in compilerResults.Errors)
                    {
                        errorTexts.Add(error.ErrorText);
                    }
                    throw new Exception("Compilation failed: " + string.Join("; ", errorTexts.ToArray()));
                }
                assemblyBytes = File.ReadAllBytes(compilerResults.PathToAssembly);
                File.Delete(compilerResults.PathToAssembly);
            }
            catch (Exception)
            {
                // surface to the caller (CLI prints it and exits; interactive shows
                // it and returns to the menu) instead of killing the process
                throw;
            }

            return assemblyBytes;
        }
    }
}
