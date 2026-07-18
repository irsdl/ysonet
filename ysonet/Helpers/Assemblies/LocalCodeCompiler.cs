using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ysonet.Helpers
{
    public static class LocalCodeCompiler
    {

        public static byte[] GetAsmBytes(string fileChain)
        {
            if (fileChain.EndsWith(".dll") && !fileChain.Contains(".cs;"))
            {
                // we have a DLL file
                return GetAsmBytesFromDLL(fileChain);
            }
            else
            {
                // we need to compile the code
                return CompileToAsmBytes(fileChain, "", "");
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

                string[] files = fileChain.Split(new[] { ';' }).Select(s => s.Trim()).ToArray();
                CodeDomProvider codeDomProvider = CodeDomProvider.CreateProvider(compilerLanguage);
                CompilerParameters compilerParameters = new CompilerParameters();
                compilerParameters.CompilerOptions = compilerOptions;
                compilerParameters.ReferencedAssemblies.AddRange(files.Skip(1).ToArray());
                CompilerResults compilerResults = codeDomProvider.CompileAssemblyFromFile(compilerParameters, files[0]);
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
