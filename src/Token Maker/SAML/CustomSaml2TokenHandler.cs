using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace CommonWell.Tools.SAML
{
    public class CustomSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public override bool CanValidateToken
        {
            get { return true; }
        }

        protected override void WriteAttributeValue(XmlWriter writer, string value, Saml2Attribute attribute)
        {
            var sb = new StringBuilder("<a>");
            sb.Append(value);
            sb.Append("</a>");
            byte[] rawValue = new UTF8Encoding().GetBytes(sb.ToString());
            XmlDictionaryReader reader = XmlDictionaryReader.CreateTextReader(rawValue, XmlDictionaryReaderQuotas.Max);
            reader.ReadStartElement("a");
            while (reader.NodeType != XmlNodeType.EndElement || (reader.NodeType == XmlNodeType.EndElement && reader.Name != "a"))
            {
                writer.WriteNode(reader, false);
            }
            reader.ReadEndElement();
            reader.Close();
        }
    }
}
