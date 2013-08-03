using System;

namespace CommonWell.Tools.SAML
{
    public class RoleClaim
    {
        public string Code;
        public string DisplayName;

        public RoleClaim(string name, string code)
        {
            Code = code;
            DisplayName = name;
        }


        public override string ToString()
        {
            const string template =
                @"<Role xmlns=""urn:hl7-org:v3"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""CE"" code=""{0}"" codeSystem=""2.16.840.1.113883.6.96"" codeSystemName=""SNOMED_CT"" displayName=""{1}""/>";
            return String.Format(template, Code, DisplayName);
        }
    }
}