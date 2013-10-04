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