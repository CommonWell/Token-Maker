using System;

namespace CommonWell.Tools.SAML
{
    public class PurposeOfUseClaim
    {
        public string Code;
        public string DisplayName;

        public PurposeOfUseClaim(string name, string code)
        {
            Code = code;
            DisplayName = name;
        }

        public override string ToString()
        {
            const string template =
                @"<PurposeOfUse xmlns=""urn:hl7-org:v3"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""CE"" code=""{0}"" codeSystem=""2.16.840.1.113883.3.18.7.1"" codeSystemName=""nhin-purpose"" displayName=""{1}""/>";
            return String.Format(template, Code, DisplayName);
        }
    }
}