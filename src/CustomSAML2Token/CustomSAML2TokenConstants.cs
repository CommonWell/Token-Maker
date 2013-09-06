// ====================================================================
// Solution: Token Maker
// Project: CustomSAML2Token
// File: CustomSAML2TokenConstants.cs
//  
// Created: 08-24-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

namespace CommonWell.Tools
{
    public static class CustomSAML2TokenConstants
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

    public  static class DigestAlgorithm
    {
        public const string Sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        public const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    }
}

