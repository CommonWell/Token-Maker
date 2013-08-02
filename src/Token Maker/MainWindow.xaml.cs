using System;
using System.Collections.Generic;
using System.IO;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Xml;
using CommonWell.Tools.Properties;
using CommonWell.Tools.SAML;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using Formatting = Newtonsoft.Json.Formatting;

namespace CommonWell.Tools
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            PopulateSubjectRoles();
            PopulatePurposeOfUse();
            DateExpiration.Value = DateTime.Now.AddMinutes(5).ToUniversalTime();
            SetControlsFromSettings();
        }

        private void SetControlsFromSettings()
        {
            CertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            TxtPassphrase.Text = Settings.Default.Passphrase;
        }

        private void PopulateSubjectRoles()
        {
            var subjectRoles = new List<ComboBoxPairs>
                {
                    new ComboBoxPairs("Medical doctor", "112247003"),
                    new ComboBoxPairs("Hospital nurse", "394618009"),
                    new ComboBoxPairs("Pharmacist", " 46255001"),
                    new ComboBoxPairs("Admnistrator", " 308050009")
                };
            CmbSubjectRole.ItemsSource = subjectRoles;
            CmbSubjectRole.DisplayMemberPath = "Key";
            CmbSubjectRole.SelectedValuePath = "Value";
            CmbSubjectRole.SelectedItem = subjectRoles.First();
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
            CmbPurposeOfUse.ItemsSource = purposes;
            CmbPurposeOfUse.DisplayMemberPath = "Key";
            CmbPurposeOfUse.SelectedValuePath = "Value";
            CmbPurposeOfUse.SelectedItem = purposes.First();
        }

        private void Encode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                TxtTokenString.Text = BuildJwtToken();
                DecodeJwtToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Decode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
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
                TextBoxSamlToken.Text = BuildSamlToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecodeJwtToken()
        {
            TxtSignature.Clear();
            TxtHeader.Clear();
            TxtBody.Clear();
            ParseToken(TxtTokenString.Text);
        }

        private void ParseToken(string token)
        {
            string[] parts = token.Split('.');
            JObject jsonPart = JObject.Parse(DecodeFrom64(parts[0]));
            TxtHeader.Text = jsonPart.ToString(Formatting.Indented);

            jsonPart = JObject.Parse(DecodeFrom64(parts[1]));
            TxtBody.Text = jsonPart.ToString(Formatting.Indented);

            TxtSignature.Text = parts[2];
        }

        private string BuildJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var certificate =
                new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
            var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("subjectId", TxtSubject.Text),
                            new Claim("subjectRole", CmbSubjectRole.SelectedValue.ToString()),
                            new Claim("organization", TxtOrganization.Text),
                            new Claim("organizationId", TxtOrganizationId.Text),
                            new Claim("purposeOfUse", CmbPurposeOfUse.SelectedValue.ToString()),
                            new Claim("npi", TxtNpi.Text)
                        }),
                    TokenIssuerName = "self",
                    TokenType = "JWT",
                    AppliesToAddress = "urn:commonwellalliance.org",
                    Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value),
                    SigningCredentials = new X509SigningCredentials(certificate)
                };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private void ChooseCertificate_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog { DefaultExt = ".pfx", Filter = "Certificates (.pfx, .p12)|*.pfx; *.p12" };
            bool? result = dlg.ShowDialog();

            if (result == true)
            {
                Settings.Default.CertificatePath = dlg.FileName;
                CertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Save();
            Close();
        }

        private static string DecodeFrom64(string encodedData)
        {
            int padding = encodedData.Length % 4;
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
            if (TxtPassphrase.Text != Settings.Default.Passphrase)
            {
                Settings.Default.Passphrase = TxtPassphrase.Text;
            }
        }

        private string BuildSamlToken()
        {
            var tokenHandler = new CustomSaml2SecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:subject-id", TxtSubject.Text),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:organization", TxtOrganization.Text),
                            new Claim("urn:oasis:names:tc:xacml:2.0:subject:role",
                                      new RoleClaim(CmbSubjectRole.Text, CmbSubjectRole.SelectedValue.ToString())
                                          .ToString()),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:purposeofuse",
                                      new PurposeOfUseClaim(CmbPurposeOfUse.Text,
                                                            CmbPurposeOfUse.SelectedValue.ToString()).ToString()),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:organization-id", TxtOrganizationId.Text),
                            new Claim("urn:oasis:names:tc:xspa:2.0:subject:npi", TxtNpi.Text)
                        }),
                    TokenIssuerName = "self",
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
                    AppliesToAddress = "urn:commonwellalliance.org",
                    Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value)
                };
            if (ToggleSignSamlToken.IsChecked != null && (bool) ToggleSignSamlToken.IsChecked)
            {
                var certificate = new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
                tokenDescriptor.SigningCredentials = new X509SigningCredentials(certificate);
            }
            var token = tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
            var settings = new XmlWriterSettings();
            settings.Indent = true;
            var sbuilder = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sbuilder, settings))
            {
                if (token != null) tokenHandler.WriteToken(writer, token);
            }
            return sbuilder.ToString();
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

        private void ToggleSignSAMLToken_Checked(object sender, RoutedEventArgs e)
        {
            ToggleSignSamlToken.Content = "Signed Token";
            ToggleSignSamlToken.Foreground = new SolidColorBrush(Colors.Green);
        }

        private void ToggleSignSamlToken_Unchecked(object sender, RoutedEventArgs e)
        {
            ToggleSignSamlToken.Content = "Unsigned Token";
            ToggleSignSamlToken.Foreground = new SolidColorBrush(Colors.Red);
        }

        private void TxtPassphrase_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            SavePassphrase();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Settings.Default.Save();
        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Reset();
            SetControlsFromSettings();
        }
    }
}