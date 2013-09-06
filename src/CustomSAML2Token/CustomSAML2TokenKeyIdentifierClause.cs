// ====================================================================
// Solution: Token Maker
// Project: CustomSAML2Token
// File: CustomSAML2TokenKeyIdentifierClause.cs
//  
// Created: 08-24-2013
//  
// (c) 2013 RelayHealth and its affiliates. All rights reserved.
// ====================================================================

using System;
using System.IdentityModel.Tokens;

namespace CommonWell.Tools
{
    public class CustomSAML2TokenKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        private const string LocalId = "CustomSAML2Token";
        private readonly string _audience;

        public CustomSAML2TokenKeyIdentifierClause(string audience)
            : base(LocalId)
        {
            if (audience == null)
            {
                throw new ArgumentNullException("audience");
            }
            _audience = audience;
        }

        public string Audience
        {
            get { return _audience; }
        }

        public override bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (keyIdentifierClause is CustomSAML2TokenKeyIdentifierClause)
            {
                return true;
            }

            return false;
        }
    }
}