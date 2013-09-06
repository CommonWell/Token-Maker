// ====================================================================
// Solution: Token Maker
// Project: Token Maker
// File: CustomSaml2TokenConstants.cs
//  
// Created: 08-24-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

namespace CommonWell.Tools.SAML
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
}