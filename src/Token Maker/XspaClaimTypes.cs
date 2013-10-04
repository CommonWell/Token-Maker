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

namespace CommonWell.Tools
{
    /// <summary>
    ///     Claims defined in the Cross-Enterprise Security and Privacy Authorization (XSPA) profile.
    /// </summary>
    public static class XspaClaimTypes
    {
        /// <summary>
        ///     SubjectIdentifier.
        /// </summary>
        public const string SubjectIdentifier = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

        /// <summary>
        ///     SubjectOrganization.
        /// </summary>
        public const string SubjectOrganization = "urn:oasis:names:tc:xpsa:1.0:subject:organization";

        /// <summary>
        ///     SubjectRole.
        /// </summary>
        public const string SubjectRole = "urn:oasis:names:tc:xacml:2.0:subject:role";

        /// <summary>
        ///     PurposeOfUse.
        /// </summary>
        public const string PurposeOfUse = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";

        /// <summary>
        ///     OrganizationIdentifier.
        /// </summary>
        public const string OrganizationIdentifier = "urn:oasis:names:tc:xspa:1.0:subject:organization-id";

        /// <summary>
        ///     NationalProviderIdentifier.
        /// </summary>
        public const string NationalProviderIdentifier = "urn:oasis:names:tc:xspa:2.0:subject:npi";

        /// <summary>
        ///     The address that a claim applies to.
        /// </summary>
        public const string AppliesToAddress = "urn:commonwellalliance.org";
    }
}