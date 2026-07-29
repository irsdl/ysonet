namespace ysonet.Tests
{
    /// <summary>
    /// A stand-in with one shape and nothing else: a public string property that has a SETTER
    /// AND NO GETTER, exactly like
    /// System.Activities.Presentation.WorkflowDesigner.PropertyInspectorFontAndColorData.
    ///
    /// It exists because that shape - not the usual "does this serializer assign members by
    /// name" question - is what decides the WorkflowDesigner gadget's formatter list, and the
    /// rule needs measuring rather than assuming. Measuring it on the real target is a bad
    /// trade: constructing a WorkflowDesigner creates a WPF System.Windows.Application inside
    /// whichever process does it, which is why the gadget's fire rows run in a child process.
    /// This type constructs in a nanosecond and touches nothing.
    ///
    /// The static recorder is the point. A write-only property cannot report what it was given,
    /// so a test has no other way to tell "the serializer assigned it" from "the serializer
    /// never saw it" - and those two look identical from the outside, which is the whole trap.
    /// </summary>
    public sealed class WriteOnlyMemberProbe
    {
        /// <summary>The last value any serializer assigned, or null if none did.</summary>
        public static string LastAssigned;

        public string Assigned
        {
            set { LastAssigned = value; }
        }
    }
}
