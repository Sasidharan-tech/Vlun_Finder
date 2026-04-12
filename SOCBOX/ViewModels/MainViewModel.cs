using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace SOCBOX.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private object _currentView;
        public object CurrentView
        {
            get => _currentView;
            set { _currentView = value; OnPropertyChanged(); }
        }

        public ICommand ShowDashboardCommand { get; }
        public ICommand ShowScanCommand { get; }
        public ICommand ShowVulnsCommand { get; }
        public ICommand ShowReportsCommand { get; }
        public ICommand ShowLogsCommand { get; }
        public ICommand ShowSettingsCommand { get; }

        public MainViewModel()
        {
            ShowDashboardCommand = new RelayCommand(_ => ShowDashboard());
            ShowScanCommand = new RelayCommand(_ => ShowScan());
            ShowVulnsCommand = new RelayCommand(_ => ShowVulns());
            ShowReportsCommand = new RelayCommand(_ => ShowReports());
            ShowLogsCommand = new RelayCommand(_ => ShowLogs());
            ShowSettingsCommand = new RelayCommand(_ => ShowSettings());
            ShowDashboard();
        }

        private void ShowDashboard() => CurrentView = new Views.DashboardView();
        private void ShowScan() => CurrentView = new Views.ScanView();
        private void ShowVulns() => CurrentView = new Views.VulnerabilitiesView();
        private void ShowReports() => CurrentView = new Views.ReportsView();
        private void ShowLogs() => CurrentView = new Views.LogsView();
        private void ShowSettings() => CurrentView = new Views.SettingsView();

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;
        public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }
        public bool CanExecute(object parameter) => _canExecute == null || _canExecute(parameter);
        public void Execute(object parameter) => _execute(parameter);
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}
