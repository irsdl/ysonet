using System;
using System.Collections.Generic;
using System.IO;
using static ysonet.Helpers.CommandArgSplitter;

namespace ysonet.Helpers
{
    public class InputArgs
    {
        private string _cmdFileName; // set internally using _cmdRawNoEncoding (Cmd)
        private string _cmdArguments; // set internally using _cmdRawNoEncoding (Cmd)
        private string _cmdFromFile; // can be set internally using _cmdRawNoEncoding (Cmd)
        private string _cmdRawNoEncoding; // Cmd
        private bool _hasArguments; // set internally using _cmdRawNoEncoding (Cmd)
        private CommandType _cmdType = CommandType.None;

        private bool _test = false;
        private bool _testClr2 = false;
        private bool _minify = false;
        private bool _useSimpleType = false;
        private bool _isRawCmd = false;
        private bool _isDebugMode = false;
        private bool _isSTAThread = false; // this is for when STAThreadAttribute is needed to execute!
        private bool _dosAcknowledged = false; // the user accepted the denial-of-service warning (--i-understand-dos)
        private bool _legacyFx = false; // rewrite framework assembly identities to the CLR-v2 ones (--legacyfx)
        private List<String> _extraArguments = new List<string>();
        private List<String> _extraInternalArguments = new List<string>(); // This is used as ExtraArguments when calling GenerateWithNoTest to stop passing unwanted extra options 

        public InputArgs() { }

        public InputArgs(string cmd, bool rawcmd, bool test, bool minify, bool useSimpleType, bool isDebugMode, List<String> extraArguments)
        {
            this.Cmd = cmd;
            this.IsRawCmd = rawcmd;
            this.Test = test;
            this.Minify = minify;
            this.UseSimpleType = useSimpleType;
            this.IsDebugMode = isDebugMode;
            if (extraArguments != null)
                this.ExtraArguments = extraArguments;
        }

        public string CmdFullString
        {
            get
            {
                string tempFullCmd;

                if (IsRawCmd)
                {
                    tempFullCmd = this.Cmd;
                }
                else
                {
                    tempFullCmd = "cmd /c " + this.Cmd;
                }

                bool hasArgs;
                string[] splittedCmd = CommandArgSplitter.SplitCommand(tempFullCmd, this.CmdType, out hasArgs);

                this.CmdFileName = splittedCmd[0];

                this.HasArguments = hasArgs;

                if (hasArgs)
                {
                    this.CmdArguments = splittedCmd[1];
                }

                tempFullCmd = String.Join(" ", splittedCmd);
                return tempFullCmd;

            }

        }

        public string CmdFileName
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdFileName;
                }
                else
                {
                    return "";
                }

            }

            private set
            {
                _cmdFileName = value;
            }
        }

        public string CmdArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdArguments;
                }
                else
                {
                    return "";
                }

            }

            private set
            {
                _cmdArguments = value;
            }
        }

        public string Cmd
        {
            get
            {
                return _cmdRawNoEncoding;
            }

            set
            {
                _cmdRawNoEncoding = value;
            }
        }

        // this is when cmd is used to read from a file
        // return null if cmd is not a file
        public string CmdFromFile
        {
            get
            {
                if (File.Exists(Cmd))
                {
                    Console.Error.WriteLine("Reading command from file " + Cmd + " ...");
                    _cmdFromFile = File.ReadAllText(Cmd);
                }
                else
                {
                    _cmdFromFile = null;
                }

                return _cmdFromFile;
            }

            set
            {
                _cmdFromFile = value;
            }
        }

        public bool Test
        {
            get
            {
                return _test;
            }

            set
            {
                _test = value;
            }
        }

        // True when Test should deserialize in the separately shipped CLR2 victim instead of
        // this CLR4 process (--testclr2). Test remains true as well so every existing gadget
        // follows its normal self-test generation path; the shared runner chooses the process.
        public bool TestClr2
        {
            get
            {
                return _testClr2;
            }

            set
            {
                _testClr2 = value;
                if (value)
                    _test = true;
            }
        }

        public bool Minify
        {
            get
            {
                return _minify;
            }

            set
            {
                _minify = value;
            }
        }

        public bool UseSimpleType
        {
            get
            {
                return _useSimpleType;
            }

            set
            {
                _useSimpleType = value;
            }
        }

        public bool IsRawCmd
        {
            get
            {
                return _isRawCmd;
            }

            set
            {
                _isRawCmd = value;
            }
        }

        public CommandType CmdType
        {
            get
            {
                return _cmdType;
            }

            set
            {
                _cmdType = value;
            }
        }

        public bool HasArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _hasArguments;
                }
                else
                {
                    return false;
                }

            }

            private set
            {
                _hasArguments = value;
            }
        }

        public List<string> ExtraArguments
        {
            get
            {
                if (_extraArguments == null)
                    return new List<string>();

                return _extraArguments;
            }

            set
            {
                _extraArguments = value;
            }
        }

        public bool IsDebugMode
        {
            get
            {
                return _isDebugMode;
            }

            set
            {
                _isDebugMode = value;
            }
        }

        public List<string> ExtraInternalArguments
        {
            get
            {
                if (_extraInternalArguments == null)
                    return new List<string>();

                return _extraInternalArguments;
            }

            set
            {
                _extraInternalArguments = value;
            }
        }

        public bool IsSTAThread
        {
            get
            {
                return _isSTAThread;
            }

            set
            {
                _isSTAThread = value;
            }
        }

        // The user acknowledged that a denial-of-service gadget can disrupt or
        // terminate the target process (--i-understand-dos). This is global
        // execution context, not a gadget option: it is kept as its own property
        // and never placed in ExtraArguments, where a gadget's option parsing
        // would see it. Default false, so nothing is ever acknowledged by accident.
        public bool DosAcknowledged
        {
            get
            {
                return _dosAcknowledged;
            }

            set
            {
                _dosAcknowledged = value;
            }
        }

        // Ask for the CLR-v2 generation (.NET Framework 2.0/3.0/3.5) assembly identities in
        // every payload layer that has one (--legacyfx). Like Minify it is GENERATION
        // CONTEXT, not a gadget option: it is kept as its own property and never placed in
        // ExtraArguments, where a gadget's option parsing would see it. Default false, so a
        // normal run is byte for byte what it always was.
        //
        // It is a requested TRANSFORM and never a compatibility claim: see
        // Helpers/Serialization/LegacyFrameworkIdentities.cs.
        public bool LegacyFx
        {
            get
            {
                return _legacyFx;
            }

            set
            {
                _legacyFx = value;
            }
        }

        public InputArgs ShallowCopy()
        {
            return (InputArgs)this.MemberwiseClone();
        }

        public InputArgs DeepCopy()
        {
            InputArgs newInputArgs = new InputArgs();
            newInputArgs.Cmd = this._cmdRawNoEncoding;
            newInputArgs.IsRawCmd = this._isRawCmd;
            newInputArgs.Test = this._test;
            newInputArgs.TestClr2 = this._testClr2;
            newInputArgs.Minify = this._minify;
            newInputArgs.UseSimpleType = this._useSimpleType;
            newInputArgs.ExtraArguments = this.ExtraArguments;
            newInputArgs.ExtraInternalArguments = this.ExtraInternalArguments;
            newInputArgs.IsDebugMode = this.IsDebugMode;
            newInputArgs.DosAcknowledged = this._dosAcknowledged;
            newInputArgs.LegacyFx = this._legacyFx;
            return newInputArgs;
        }

    }
}
