using System;

namespace CommonWell.Tools.SAML
{
    //  codeSystemName="SNOMED CT" displayName="Medical doctor"/>
    /// <summary>
    ///     <Role xmlns="urn:hl7-org:v3" xsi:type="CE" code="112247003"
    ///         codeSystem="2.16.840.1.113883.6.96"
    /// </summary>
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
                @"<Role xmlns=""urn:hl7-org:v3"" type=""hl7:CE"" code=""{0}"" codeSystem=""2.16.840.1.113883.6.96"" codeSystemName=""SNOMED CT"" displayName=""{1}""/>";
            return String.Format(template, Code, DisplayName);
        }
    }
}