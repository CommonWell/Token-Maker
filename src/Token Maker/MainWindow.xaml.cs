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

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Xml;
using System.Xml.Linq;
using CommonWell.Tools.Properties;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using Formatting = Newtonsoft.Json.Formatting;

namespace CommonWell.Tools
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        public MainWindow()
        {
            InitializeComponent();
            PopulateSubjectRoles();
            PopulatePurposeOfUse();
            PopulateAlgorithms();
            PopulateSAMLConfirmations();
            DateExpiration.Value = DateTime.Now.AddMinutes(5).ToUniversalTime();
            SetControlsFromSettings();
        }

        private void SetControlsFromSettings()
        {
            LabelCertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            TextBoxPassphrase.Text = Settings.Default.Passphrase;
        }

        private void PopulateSubjectRoles()
        {
            // Common roles with associated SNOMED codes
            var subjectRoles = new List<ComboBoxPairs>
            {
                new ComboBoxPairs("Medical doctor", "112247003"),
                new ComboBoxPairs("Hospital nurse", "394618009"),
                new ComboBoxPairs("Pharmacist", "46255001"),
                new ComboBoxPairs("Admnistrator", "308050009")
            };
            ComboBoxSubjectRole.ItemsSource = subjectRoles;
            ComboBoxSubjectRole.DisplayMemberPath = "Key";
            ComboBoxSubjectRole.SelectedValuePath = "Value";
            ComboBoxSubjectRole.SelectedItem = subjectRoles.First();
        }

        private void PopulateSAMLConfirmations()
        {
            var confirmations = new List<ComboBoxPairs>
            {
                new ComboBoxPairs("Bearer", "bearer"),
                new ComboBoxPairs("Holder-of-Key", "holder"),
                new ComboBoxPairs("Sender Vouches", "sender")
            };
            ComboBoxConfirmation.ItemsSource = confirmations;
            ComboBoxConfirmation.DisplayMemberPath = "Key";
            ComboBoxConfirmation.SelectedValuePath = "Value";
            ComboBoxConfirmation.SelectedItem = confirmations.First();
        }

        private void PopulateAlgorithms()
        {
            var algorithms = new List<ComboBoxPairs>
            {
                new ComboBoxPairs("SHA-256", "SHA256"),
                new ComboBoxPairs("SHA-1", "SHA1")
            };
            ComboBoxSigningAlgorithm.ItemsSource = algorithms;
            ComboBoxSigningAlgorithm.DisplayMemberPath = "Key";
            ComboBoxSigningAlgorithm.SelectedValuePath = "Value";
            ComboBoxSigningAlgorithm.SelectedItem = algorithms.First();

            ComboBoxDigestAlgorithm.ItemsSource = algorithms;
            ComboBoxDigestAlgorithm.DisplayMemberPath = "Key";
            ComboBoxDigestAlgorithm.SelectedValuePath = "Value";
            ComboBoxDigestAlgorithm.SelectedItem = algorithms.First();
        }

        private void PopulatePurposeOfUse()
        {
            var purposes = new List<ComboBoxPairs>
            {
                new ComboBoxPairs("Treatment", "TREATMENT"),
                new ComboBoxPairs("Payment", "PAYMENT"),
                new ComboBoxPairs("Healthcare Operations", "OPERATIONS"),
                new ComboBoxPairs("Systems Administration", "SYSADMIN"),
                new ComboBoxPairs("Fraud detection", "FRAUD"),
                new ComboBoxPairs("Disclosure of Psychotherapy Notes", "PSYCHOTHERAPY"),
                new ComboBoxPairs("Training", "TRAINING"),
                new ComboBoxPairs("Legal", "LEGAL"),
                new ComboBoxPairs("Marketing", "MARKETING"),
                new ComboBoxPairs("Facility directories", "DIRECTORY"),
                new ComboBoxPairs("Disclosure to family member", "FAMILY"),
                new ComboBoxPairs("Disclosure with individual Present", "PRESENT"),
                new ComboBoxPairs("Emergency disclosure", "EMERGENCY"),
                new ComboBoxPairs("Disaster relief", "DISASTER"),
                new ComboBoxPairs("Public health activities", "PUBLICHEALTH"),
                new ComboBoxPairs("Disclosure about victim of abuse", "ABUSE"),
                new ComboBoxPairs("Oversight activities", "OVERSIGHT"),
                new ComboBoxPairs("Judicial proceedings", "JUDICIAL"),
                new ComboBoxPairs("Law enforcement", "LAW"),
                new ComboBoxPairs("Disclosure about decedent", "DECEASED"),
                new ComboBoxPairs("Organ donation", "DONATION"),
                new ComboBoxPairs("Dsclosure for research", "RESEARCH"),
                new ComboBoxPairs("Disclosure to avert threat", "THREAT"),
                new ComboBoxPairs("Specialized government function", "GOVERNMENT"),
                new ComboBoxPairs("Worker's compensation", "WORKERSCOMP"),
                new ComboBoxPairs("Insurance/Disability coverage", "COVERAGE"),
                new ComboBoxPairs("Request of the individual", "REQUEST")
            };
            ComboBoxPurposeOfUse.ItemsSource = purposes;
            ComboBoxPurposeOfUse.DisplayMemberPath = "Key";
            ComboBoxPurposeOfUse.SelectedValuePath = "Value";
            ComboBoxPurposeOfUse.SelectedItem = purposes.First();
        }

        private void EncodeJwt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                TextBoxJwtSignature.Clear();
                TextBoxJwtHeader.Clear();
                TextBoxJwtBody.Clear();
                if (!IsCertificateLoaded()) return;
                TextBoxJwtToken.Text = BuildJwtToken();
                DecodeJwtToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecodeJwt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!IsCertificateLoaded()) return;
                DecodeJwtToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SAML_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!IsCertificateLoaded()) return;
                TextBoxSamlToken.Text = BuildSamlToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static bool IsCertificateLoaded()
        {
            bool returnValue = true;
            if (Path.IsPathRooted(Settings.Default.CertificatePath) == false)
            {
                MessageBox.Show("Select an X.509 Certificate", "X.509 Certificate Required", MessageBoxButton.OK,
                    MessageBoxImage.Exclamation);
                returnValue = false;
            }
            return returnValue;
        }

        private void DecodeJwtToken()
        {
            TextBoxJwtSignature.Clear();
            TextBoxJwtHeader.Clear();
            TextBoxJwtBody.Clear();
            if (String.IsNullOrEmpty(TextBoxJwtToken.Text)) return;
            ParseToken(TextBoxJwtToken.Text);
        }

        private void ParseToken(string token)
        {
            string[] parts = token.Split('.');
            JObject jsonPart = JObject.Parse(DecodeFromBase64(parts[0]));
            TextBoxJwtHeader.Text = jsonPart.ToString(Formatting.Indented);

            jsonPart = JObject.Parse(DecodeFromBase64(parts[1]));
            TextBoxJwtBody.Text = jsonPart.ToString(Formatting.Indented);

            TextBoxJwtSignature.Text = parts[2];
        }

        private string BuildJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var certificate = new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
            SecurityTokenDescriptor tokenDescriptor = (Iua.IsChecked.HasValue && Iua.IsChecked.Value)
                ? BuildDescriptorUsingIUAProfile()
                : BuildJWTDescriptorUsingXspaProfile();
            tokenDescriptor.TokenType = "JWT";
            tokenDescriptor.SigningCredentials = new X509SigningCredentials(certificate);
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        private SecurityTokenDescriptor BuildDescriptorUsingIUAProfile()
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(IUAClaimTypes.JWTId, Guid.NewGuid().ToString()),
                    new Claim(IUAClaimTypes.Subject, TextBoxSubject.Text),
                    new Claim(IUAClaimTypes.SubjectIdentifier, TextBoxSubject.Text),
                    new Claim(IUAClaimTypes.SubjectRole, ComboBoxSubjectRole.SelectedValue.ToString()),
                    new Claim(IUAClaimTypes.SubjectOrganization, TextBoxOrganization.Text),
                    new Claim(IUAClaimTypes.OrganizationIdentifier, TextBoxOrganizationId.Text),
                    new Claim(IUAClaimTypes.PurposeOfUse, ComboBoxPurposeOfUse.SelectedValue.ToString())
                }),
                TokenIssuerName = SetTokenIssuerName(),
                AppliesToAddress = IUAClaimTypes.AppliesToAddress,
                Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value),
            };
            if (!String.IsNullOrEmpty(TextBoxNpi.Text))
            {
                tokenDescriptor.Subject.AddClaim(new Claim(IUAClaimTypes.NationalProviderIdentifier, TextBoxNpi.Text));
            }
            return tokenDescriptor;
        }

        private SecurityTokenDescriptor BuildSAMLDescriptorUsingXspaProfile()
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(XspaClaimTypes.SubjectIdentifier, TextBoxSubject.Text),
                    new Claim(XspaClaimTypes.SubjectRole,
                        new RoleClaim(ComboBoxSubjectRole.Text, ComboBoxSubjectRole.SelectedValue.ToString()).ToString()),
                    new Claim(XspaClaimTypes.SubjectOrganization, TextBoxOrganization.Text),
                    new Claim(XspaClaimTypes.OrganizationIdentifier, TextBoxOrganizationId.Text),
                    new Claim(XspaClaimTypes.PurposeOfUse,
                        new PurposeOfUseClaim(ComboBoxPurposeOfUse.Text, ComboBoxPurposeOfUse.SelectedValue.ToString())
                            .ToString())
                }),
                TokenIssuerName = SetTokenIssuerName(),
                AppliesToAddress = IUAClaimTypes.AppliesToAddress,
                Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value),
            };
            if (!String.IsNullOrEmpty(TextBoxNpi.Text))
            {
                tokenDescriptor.Subject.AddClaim(new Claim(XspaClaimTypes.NationalProviderIdentifier, TextBoxNpi.Text));
            }
            return tokenDescriptor;
        }

        private SecurityTokenDescriptor BuildJWTDescriptorUsingXspaProfile()
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(XspaClaimTypes.SubjectIdentifier, TextBoxSubject.Text),
                    new Claim(XspaClaimTypes.SubjectRole, ComboBoxSubjectRole.SelectedValue.ToString()),
                    new Claim(XspaClaimTypes.SubjectOrganization, TextBoxOrganization.Text),
                    new Claim(XspaClaimTypes.OrganizationIdentifier, TextBoxOrganizationId.Text),
                    new Claim(XspaClaimTypes.PurposeOfUse, ComboBoxPurposeOfUse.SelectedValue.ToString())
                }),
                TokenIssuerName = SetTokenIssuerName(),
                AppliesToAddress = IUAClaimTypes.AppliesToAddress,
                Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value),
            };
            if (!String.IsNullOrEmpty(TextBoxNpi.Text))
            {
                tokenDescriptor.Subject.AddClaim(new Claim(XspaClaimTypes.NationalProviderIdentifier, TextBoxNpi.Text));
            }
            return tokenDescriptor;
        }

        private string SetTokenIssuerName()
        {
            return (string.IsNullOrEmpty(TextBoxIssuer.Text.Trim(' ')) ? "self" : TextBoxIssuer.Text);
        }

        private void ChooseCertificate_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog {DefaultExt = ".pfx", Filter = "Certificates (.pfx, .p12)|*.pfx; *.p12"};
            bool? result = dlg.ShowDialog();

            if (result == true)
            {
                Settings.Default.CertificatePath = dlg.FileName;
                LabelCertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Save();
            Close();
        }

        private static string DecodeFromBase64(string encodedData)
        {
            int padding = encodedData.Length%4;
            if (padding > 0)
            {
                encodedData += new string('=', (4 - padding));
            }
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            string returnValue = Encoding.ASCII.GetString(encodedDataAsBytes);

            return returnValue;
        }

        private void TxtPassphrase_LostFocus(object sender, RoutedEventArgs e)
        {
            SavePassphrase();
        }

        private void SavePassphrase()
        {
            if (TextBoxPassphrase.Text != Settings.Default.Passphrase)
            {
                Settings.Default.Passphrase = TextBoxPassphrase.Text;
            }
        }

        private string BuildSamlToken()
        {
            var certificate = new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
            string signingAlgorithm = SignatureAlgorithm.Sha256;
            string digestAlgorithm = DigestAlgorithm.Sha256;
            SigningCredentials signingCredentials = null;

            switch (ComboBoxSigningAlgorithm.SelectedValue.ToString())
            {
                case "SHA1":
                    signingAlgorithm = SignatureAlgorithm.Sha1;
                    break;
                case "SHA256":
                    signingAlgorithm = SignatureAlgorithm.Sha256;
                    break;
            }

            switch (ComboBoxDigestAlgorithm.SelectedValue.ToString())
            {
                case "SHA1":
                    digestAlgorithm = DigestAlgorithm.Sha1;
                    break;
                case "SHA256":
                    digestAlgorithm = DigestAlgorithm.Sha256;
                    break;
            }

            if (Rsa.IsChecked.HasValue && Rsa.IsChecked.Value)
            {
                var rsa = certificate.PrivateKey as RSACryptoServiceProvider;
                if (rsa != null)
                {
                    var rsaKey = new RsaSecurityKey(rsa);
                    var rsaClause = new RsaKeyIdentifierClause(rsa);
                    var ski = new SecurityKeyIdentifier(new SecurityKeyIdentifierClause[] {rsaClause});
                    signingCredentials = new SigningCredentials(rsaKey, signingAlgorithm, digestAlgorithm, ski);
                }
            }
            else
            {
                var clause =
                    new X509SecurityToken(certificate).CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>();
                var ski = new SecurityKeyIdentifier(clause);
                signingCredentials = new X509SigningCredentials(certificate, ski, signingAlgorithm, digestAlgorithm);
            }

            SecurityTokenDescriptor tokenDescriptor = BuildSAMLDescriptorUsingXspaProfile();
            tokenDescriptor.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            tokenDescriptor.SigningCredentials = signingCredentials;

            if (CheckBoxEncrypt.IsChecked.HasValue && CheckBoxEncrypt.IsChecked.Value)
            {
                const string keyWrapAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
                const string encryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
                var encryptingCredentials = new EncryptedKeyEncryptingCredentials(certificate, keyWrapAlgorithm, 256,
                    encryptionAlgorithm);
                tokenDescriptor.EncryptingCredentials = encryptingCredentials;
            }

            switch (ComboBoxConfirmation.SelectedValue.ToString())
            {
                case "holder":
                    tokenDescriptor.Proof = CreateProofDescriptor(certificate);
                    break;
                case "sender":
                    //TODO: need to find way to update SubjectConfirmation Method
                    break;
            }

            var tokenHandler = new CustomSaml2SecurityTokenHandler();
            tokenDescriptor.AddAuthenticationClaims("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
            var token = tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            var settings = new XmlWriterSettings {Indent = false, Encoding = Encoding.Default};
            var sbuilder = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sbuilder, settings))
            {
                if (token != null) tokenHandler.WriteToken(writer, token);
            }
            var tokenString = sbuilder.ToString();
            return tokenString;
        }

        private static SymmetricProofDescriptor CreateProofDescriptor(X509Certificate2 encryptingCertificate)
        {
            return new SymmetricProofDescriptor(
                256,
                new X509EncryptingCredentials(encryptingCertificate));
        }

        private void TxtPassphrase_TextChanged(object sender, TextChangedEventArgs e)
        {
            SavePassphrase();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            Settings.Default.Save();
        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Reset();
            SetControlsFromSettings();
        }

        private void CheckBoxEncrypt_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxEncrypt.Content = "Encryption ON";
        }

        private void CheckBoxEncrypt_Unchecked(object sender, RoutedEventArgs e)
        {
            CheckBoxEncrypt.Content = "Encryption OFF";
        }

        private void Rsa_Checked(object sender, RoutedEventArgs e)
        {
            ComboBoxSigningAlgorithm.SelectedValue = "SHA1";
            ComboBoxSigningAlgorithm.IsHitTestVisible = false;
            ComboBoxSigningAlgorithm.Focusable = false;
        }

        private void Rsa_Unchecked(object sender, RoutedEventArgs e)
        {
            ComboBoxSigningAlgorithm.IsHitTestVisible = true;
            ComboBoxSigningAlgorithm.Focusable = true;
        }

        private void IndentSAML_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TextBoxSamlToken.Text)) return;

            TextBoxSamlToken.Text = XDocument.Parse(TextBoxSamlToken.Text, LoadOptions.SetLineInfo).ToString();
        }

        private void SAMLValidate_Click(object sender, RoutedEventArgs e)
        {
            TreeViewValidatedClaims.Items.Clear();

            if (string.IsNullOrEmpty(TextBoxSamlToken.Text)) return;

            try
            {
                var tokenHandler = new CustomSaml2SecurityTokenHandler();
                var samlToken2 = tokenHandler.ReadToken(new XmlTextReader(new StringReader(TextBoxSamlToken.Text)));
                var identity = ValidateSamlToken(samlToken2);

                var parent = new TreeViewItem {Header = "Validated Claims"};
                foreach (var item in identity.Claims)
                {
                    if (item.Type == XspaClaimTypes.PurposeOfUse)
                    {
                        parent.Items.Add(PopulateNestedItem<PurposeOfUseClaim>(item));
                        continue;
                    }
                    if (item.Type == XspaClaimTypes.SubjectRole)
                    {
                        parent.Items.Add(PopulateNestedItem<RoleClaim>(item));
                        continue;
                    }
                    var claimItem = new TreeViewItem {Header = item.Type};
                    claimItem.Items.Add(AddItemToTree("Value", item.Value));
                    claimItem.Items.Add(AddItemToTree("Issued by", item.OriginalIssuer));
                    parent.Items.Add(claimItem);
                }
                TreeViewValidatedClaims.Items.Add(parent);
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private TreeViewItem PopulateNestedItem<T>(Claim claim) where T : NestedClaim, new()
        {
            var nestedClaim = new T();
            nestedClaim.Load(claim.Value);
            var nestedItem = new TreeViewItem() {Header = claim.Type};
            nestedItem.Items.Add(AddItemToTree("Code", nestedClaim.Code));
            nestedItem.Items.Add(AddItemToTree("Code System", nestedClaim.CodeSystem));
            nestedItem.Items.Add(AddItemToTree("Code System Name", nestedClaim.CodeSystemName));
            nestedItem.Items.Add(AddItemToTree("Display Name", nestedClaim.DisplayName));
            nestedItem.Items.Add(AddItemToTree("Type", nestedClaim.Type));
            nestedItem.Items.Add(AddItemToTree("Issued by", claim.OriginalIssuer));
            return nestedItem;
        }

        private TreeViewItem AddItemToTree(string label, string value)
        {
            return new TreeViewItem() {Header = String.Format("{0}: {1}", label, value)};
        }

        private ClaimsIdentity ValidateSamlToken(SecurityToken securityToken)
        {
            var configuration = new SecurityTokenHandlerConfiguration();
            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(configuration);
            handler.AddOrReplace(new CustomSaml2SecurityTokenHandler());
            var identity = handler.ValidateToken(securityToken).First();
            return identity;
        }

        internal class ComboBoxPairs
        {
            public ComboBoxPairs(string key, string value)
            {
                Key = key;
                Value = value;
            }

            public string Key { get; set; }
            public string Value { get; set; }
        }
    }
}