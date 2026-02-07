/*
 * File: Views/Controls/ModernButton.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Artifact: final_modern_button in claude.ai
 * Build: 2.0.20250.101
 * 
 * Description: FIXED Custom button control - resolved serialization and disposal issues
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Created modern styled button control with metallic theme
 * - v2.0.20250.101: FIXED - Added proper serialization attributes and disposal pattern
 */

using System.ComponentModel;
using System.Drawing.Drawing2D;

namespace HvcallGui.Views
{
    /// <summary>
    /// Custom button control with modern metallic styling
    /// Provides hover effects and gradient rendering for a professional appearance
    /// </summary>
    public class ModernButton : Button
    {
        #region Private Fields
        private bool _useMetallicTheme = true;
        private float _gradientIntensity = 0.3f;
        #endregion

        #region Constructor
        /// <summary>
        /// Initializes a new instance of the ModernButton with custom styling
        /// </summary>
        public ModernButton()
        {
            // Enable custom painting and transparent background support
            SetStyle(ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint |
                     ControlStyles.ResizeRedraw |
                     ControlStyles.SupportsTransparentBackColor, true);

            // Configure flat appearance for modern look
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 1;
            FlatAppearance.BorderColor = Color.FromArgb(100, 100, 100);

            // Apply metallic color scheme from UIConstants
            BackColor = UIConstants.BUTTON_BACKGROUND;
            ForeColor = UIConstants.BUTTON_FOREGROUND;
            Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            Cursor = Cursors.Hand;

            // Set default size for consistent appearance
            Size = new Size(UIConstants.BUTTON_WIDTH, UIConstants.BUTTON_HEIGHT);
        }
        #endregion

        #region Public Properties with Designer Support
        /// <summary>
        /// Gets or sets whether the button uses the metallic theme
        /// </summary>
        [Category("Appearance")]
        [Description("Determines whether the button uses the metallic theme")]
        [DefaultValue(true)]
        public bool UseMetallicTheme
        {
            get => _useMetallicTheme;
            set
            {
                _useMetallicTheme = value;
                Invalidate(); // Redraw when property changes
            }
        }

        /// <summary>
        /// Gets or sets the gradient intensity (0.0 to 1.0)
        /// </summary>
        [Category("Appearance")]
        [Description("Controls the intensity of the gradient effect (0.0 to 1.0)")]
        [DefaultValue(0.3f)]
        public float GradientIntensity
        {
            get => _gradientIntensity;
            set
            {
                _gradientIntensity = Math.Max(0.0f, Math.Min(1.0f, value));
                Invalidate(); // Redraw when property changes
            }
        }
        #endregion

        #region Protected Override Methods
        /// <summary>
        /// Handles mouse enter event to show hover effect
        /// </summary>
        /// <param name="e">Event arguments</param>
        protected override void OnMouseEnter(EventArgs e)
        {
            if (_useMetallicTheme)
            {
                BackColor = UIConstants.BUTTON_HOVER;
            }
            base.OnMouseEnter(e);
        }

        /// <summary>
        /// Handles mouse leave event to remove hover effect
        /// </summary>
        /// <param name="e">Event arguments</param>
        protected override void OnMouseLeave(EventArgs e)
        {
            if (_useMetallicTheme)
            {
                BackColor = UIConstants.BUTTON_BACKGROUND;
            }
            base.OnMouseLeave(e);
        }

        /// <summary>
        /// Custom paint method to add subtle metallic gradient effect
        /// </summary>
        /// <param name="pevent">Paint event arguments</param>
        protected override void OnPaint(PaintEventArgs pevent)
        {
            base.OnPaint(pevent);

            // Only draw gradient if enabled and client rectangle is valid
            if (_useMetallicTheme && ClientRectangle.Width > 0 && ClientRectangle.Height > 0)
            {
                // Calculate gradient colors based on intensity
                var alpha = (int)(255 * _gradientIntensity * 0.2f); // Scale down for subtlety

                // Add subtle metallic gradient overlay for depth
                using var brush = new LinearGradientBrush(
                    ClientRectangle,
                    Color.FromArgb(alpha, Color.White),     // Subtle white highlight at top
                    Color.FromArgb(alpha, Color.Black),     // Subtle black shadow at bottom
                    90F);                                   // Vertical gradient

                pevent.Graphics.FillRectangle(brush, ClientRectangle);
            }
        }

        /// <summary>
        /// Handles button click with visual feedback - FIXED disposal
        /// </summary>
        /// <param name="e">Event arguments</param>
        protected override void OnClick(EventArgs e)
        {
            if (_useMetallicTheme)
            {
                // Provide subtle visual feedback on click
                var originalColor = BackColor;
                BackColor = Color.FromArgb(Math.Max(0, originalColor.R - 30),
                                           Math.Max(0, originalColor.G - 30),
                                           Math.Max(0, originalColor.B - 30));

                // Timer is disposed in the Tick handler after it fires once
#pragma warning disable CA2000 // Dispose objects before losing scope
                var timer = new System.Windows.Forms.Timer { Interval = 100 };
#pragma warning restore CA2000
                EventHandler? timerTickHandler = null;
                timerTickHandler = (s, args) =>
                {
                    BackColor = originalColor;
                    if (timer != null)
                    {
                        timer.Tick -= timerTickHandler;
                        timer.Stop();
                        timer.Dispose();
                        timer = null;
                    }
                };
                timer.Tick += timerTickHandler;
                timer.Start();
            }

            base.OnClick(e);
        }

        /// <summary>
        /// Handles focus events to maintain consistent styling
        /// </summary>
        /// <param name="e">Event arguments</param>
        protected override void OnGotFocus(EventArgs e)
        {
            if (_useMetallicTheme)
            {
                // Add subtle focus indicator
                FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
            }
            base.OnGotFocus(e);
        }

        /// <summary>
        /// Handles lost focus events
        /// </summary>
        /// <param name="e">Event arguments</param>
        protected override void OnLostFocus(EventArgs e)
        {
            if (_useMetallicTheme)
            {
                // Restore normal border
                FlatAppearance.BorderColor = Color.FromArgb(100, 100, 100);
            }
            base.OnLostFocus(e);
        }
        #endregion
    }
}