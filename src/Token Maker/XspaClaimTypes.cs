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
    /// <summary>
    ///     Claims defined in the Cross-Enterprise Security and Privacy Authorization (XSPA) profile.
    /// </summary>
    public static class XspaClaimTypes
    {
        /// <summary>
        ///     The name of the user as required by HIPAA Privacy Disclosure Accounting.
        /// </summary>
        public const string SubjectIdentifier = "urn:oasis:names:tc:xspa:1.0:subject:subject-id";

        /// <summary>
        ///     In plain text, the organization that the user belongs to as required by HIPAA Privacy Disclosure Accounting.
        /// </summary>
        public const string SubjectOrganization = "urn:oasis:names:tc:xspa:1.0:subject:organization";

        /// <summary>
        ///     The SNOMED CT value representing the role that the user is playing when making the request.
        /// </summary>
        public const string SubjectRole = "urn:oasis:names:tc:xacml:2.0:subject:role";

        /// <summary>
        ///     The coded representation of the Purpose for Use that is in effect for the request.
        /// </summary>
        public const string PurposeOfUse = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";

        /// <summary>
        ///     This organization ID shall be consistent with the plain-text name of the organization provided in the User
        ///     Organization Attribute. The organization ID may be an Object Identifier (OID), using the urn format (that is,
        ///     "urn:oid:" appended with the OID); or it may be a URL assigned to that organization.
        /// </summary>
        public const string OrganizationIdentifier = "urn:oasis:names:tc:xspa:1.0:subject:organization-id";

        /// <summary>
        ///     A unique 10-digit identification number issued to health care providers in the United States by the Centers for
        ///     Medicare and Medicaid Services (CMS).
        /// </summary>
        public const string NationalProviderIdentifier = "urn:oasis:names:tc:xspa:2.0:subject:npi";

        /// <summary>
        ///     The Home Community ID assigned to the organization that is initiating the request, using the urn format (that is,
        ///     "urn:oid:" appended with the OID).
        /// </summary>
        public const string HomeCommunityId = "urn:nhin:names:saml:homeCommunityId";

        /// <summary>
        ///     The address that a claim applies to.
        /// </summary>
        public const string AppliesToAddress = "urn:commonwellalliance.org";
    }
}