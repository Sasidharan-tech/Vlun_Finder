using System.Windows;
using SOCBOX.ViewModels;

namespace SOCBOX.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();
        }
    }
}
