// ====================================================================
// Solution: Token Maker
// Project: Token Maker
// File: CustomSaml2TokenHandler.cs
//  
// Created: 08-01-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace CommonWell.Tools.SAML
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
            registry.AddTrustedIssuer("17bfb6a73bc53bbfdc64e4e64f77b206471e9c08","Cerner");
            var handlerConfig = new SecurityTokenHandlerConfiguration
                {
                    AudienceRestriction = new AudienceRestriction(AudienceUriMode.Never),
                    MaxClockSkew = new TimeSpan(50000000),
                    IssuerNameRegistry = registry
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

        //public override bool CanReadToken(XmlReader reader)
        //{
        //    bool canRead = false;

        //    if (reader != null)
        //    {
        //        if (reader.IsStartElement(BinarySecurityToken)
        //            && (reader.GetAttribute(ValueType) == SimpleWebTokenConstants.ValueTypeUri))
        //        {
        //            canRead = true;
        //        }
        //    }

        //    return canRead;
        //}

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException("token");
            }

            var saml2Token = token as Saml2SecurityToken;
            if (saml2Token == null)
            {
                throw new ArgumentException("The token provided must be of type Saml2SecurityToken.");
            }

            if (DateTime.Compare(saml2Token.ValidTo.Add(Configuration.MaxClockSkew), DateTime.UtcNow) <= 0)
            {
                throw new SecurityTokenExpiredException(
                    "The incoming token has expired. Get a new access token from the Authorization Server.");
            }

            //this.ValidateSignature(simpleWebToken);

            //ValidateAudience(simpleWebToken.Audience);

            ClaimsIdentity claimsIdentity = CreateClaims(saml2Token);

            //if (this.Configuration.SaveBootstrapContext)
            //{
            //    claimsIdentity.BootstrapContext = new BootstrapContext(saml2Token.SerializedToken);
            //}

            var claimCollection = new List<ClaimsIdentity>(new[] { claimsIdentity });
            return claimCollection.AsReadOnly();
        }

        protected override ClaimsIdentity CreateClaims(Saml2SecurityToken samlToken)
        {
            Console.WriteLine(samlToken.Id);
            return base.CreateClaims(samlToken);
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