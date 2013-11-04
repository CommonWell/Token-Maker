// ============================================================================
//  Copyright 2013 CommonWell Health Alliance
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

namespace CommonWell.Tools
{
    public static class CustomSaml2TokenConstants
    {
        public const string Audience = "Audience";
        public const string ExpiresOn = "ExpiresOn";
        public const string Id = "Id";
        public const string Issuer = "Issuer";
        public const string Signature = "HMACSHA256";
        public const string ValidFrom = "ValidFrom";
        public const string ValueTypeUri = "urn:oasis:names:tc:SAML:2.0:assertion";
    }

    public static class SignatureAlgorithm
    {
        public const string Sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        public const string Sha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    }

    public static class DigestAlgorithm
    {
        public const string Sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        public const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    }

    public static class WSTrust
    {
        public const string TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        public const string SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        public const int KeySize = 256;
        public const string AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
        public const string BearerKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
        public const string KeyWrapAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
        public const string EncryptWith = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string SignWith = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
        public const string CanonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public const string EncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    }
}