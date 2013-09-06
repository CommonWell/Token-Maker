// ====================================================================
// Solution: Token Maker
// Project: CustomSAML2Token
// File: CustomSaml2SecurityTokenHandler.cs
//  
// Created: 08-24-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

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
            using (var reader = XmlDictionaryReader.CreateTextReader(rawValue, XmlDictionaryReaderQuotas.Max))
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