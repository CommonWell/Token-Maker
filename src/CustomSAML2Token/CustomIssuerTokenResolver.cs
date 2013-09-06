// ====================================================================
// Solution: Token Maker
// Project: CustomSAML2Token
// File: CustomIssuerTokenResolver.cs
//  
// Created: 08-24-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

using System.Collections.Generic;
using System.IO;
using System.IdentityModel.Tokens;
using System.Text;
using System.Xml;

namespace CommonWell.Tools
{
    public class CustomIssuerTokenResolver : IssuerTokenResolver
    {
        private readonly Dictionary<string, string> _keys;

        public CustomIssuerTokenResolver()
        {
            _keys = new Dictionary<string, string>();
        }

        public void AddAudienceKeyPair(string audience, string symmetricKey)
        {
            _keys.Add(audience, symmetricKey);
        }

        public override void LoadCustomConfiguration(XmlNodeList nodelist)
        {
            if (nodelist != null)
                foreach (XmlNode node in nodelist)
                {
                    XmlDictionaryReader rdr =
                        XmlDictionaryReader.CreateDictionaryReader(new XmlTextReader(new StringReader(node.OuterXml)));
                    rdr.MoveToContent();

                    string symmetricKey = rdr.GetAttribute("symmetricKey");
                    string audience = rdr.GetAttribute("audience");

                    AddAudienceKeyPair(audience, symmetricKey);
                }
        }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause,
                                                          out SecurityKey key)
        {
            key = null;
            var keyClause = keyIdentifierClause as CustomSAML2TokenKeyIdentifierClause;
            if (keyClause != null)
            {
                string base64Key;
                _keys.TryGetValue(keyClause.Audience, out base64Key);
                if (!string.IsNullOrEmpty(base64Key))
                {
                    key = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(base64Key));
                    return true;
                }
            }

            return false;
        }
    }
}

