// ============================================================================
//  Copyright 2013 Peter Bernhardt, Trevel Beshore, et. al.
//   
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use 
//  this file except in compliance with the License. You may obtain a copy of the 
//  License at 
//  
//      http://www.apache.org/licenses/LICENSE-2.0 
//  
//  Unless required by applicable law or agreed to in writing, software distributed 
//  under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
//  CONDITIONS OF ANY KIND, either express or implied. See the License for the 
//  specific language governing permissions and limitations under the License.
// ============================================================================

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Text;
using System.Xml;

namespace CommonWell.Tools
{
    /// <summary>
    ///     Custom SAML2 Security Token Handler supporting complex attributes.
    /// </summary>
    public class CustomSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public CustomSaml2SecurityTokenHandler()
        {
            var registry = new ConfigurationBasedIssuerNameRegistry();
            registry.AddTrustedIssuer("fb369e5dcf3ae82dcbe95a922baff3112fcde352", "McKesson");
            registry.AddTrustedIssuer("17bfb6a73bc53bbfdc64e4e64f77b206471e9c08", "Cerner");
            var handlerConfig = new SecurityTokenHandlerConfiguration
            {
                AudienceRestriction = new AudienceRestriction(AudienceUriMode.BearerKeyOnly),
                MaxClockSkew = new TimeSpan(50000000),
                IssuerNameRegistry = registry,
                CertificateValidator = X509CertificateValidator.None,
                IssuerTokenResolver = new CustomIssuerTokenResolver()
            };
            Configuration = handlerConfig;
        }

        public override bool CanValidateToken
        {
            get { return true; }
        }

        public override bool CanWriteToken
        {
            get { return true; }
        }

        public override bool CanReadToken(XmlReader reader)
        {
            bool canRead = reader != null;
            return canRead;
        }

        protected override string ReadAttributeValue(XmlReader reader, Saml2Attribute attribute)
        {
            if (attribute.Name != null)
            {
                return base.ReadAttributeValue(reader, attribute);
            }
            return "empty";
        }

        protected override void WriteAttributeValue(XmlWriter writer, string value, Saml2Attribute attribute)
        {
            var sb = new StringBuilder("<a>");
            sb.Append(value);
            sb.Append("</a>");
            byte[] rawValue = new UTF8Encoding().GetBytes(sb.ToString());
            using (
                XmlDictionaryReader reader = XmlDictionaryReader.CreateTextReader(rawValue,
                    XmlDictionaryReaderQuotas.Max))
            {
                reader.ReadStartElement("a");
                while (reader.NodeType != XmlNodeType.EndElement ||
                       (reader.NodeType == XmlNodeType.EndElement && reader.Name != "a"))
                {
                    writer.WriteNode(reader, false);
                }
                reader.ReadEndElement();
                reader.Close();
            }
        }
    }
}