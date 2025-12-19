// Performance Analyzer and Optimization System
// Real-time monitoring and optimization of diary system performance

#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <unordered_map>

class HighResolutionTimer {
private:
    std::chrono::high_resolution_clock::time_point start_time;
    
public:
    HighResolutionTimer() : start_time(std::chrono::high_resolution_clock::now()) {}
    
    double elapsed_milliseconds() const {
        auto end_time = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end_time - start_time).count();
    }
    
    double elapsed_microseconds() const {
        auto end_time = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::micro>(end_time - start_time).count();
    }
    
    void reset() {
        start_time = std::chrono::high_resolution_clock::now();
    }
};

struct PerformanceMetrics {
    double request_latency_ms;
    double database_query_time_ms;
    double encryption_time_ms;
    double memory_usage_mb;
    double cpu_usage_percent;
    int active_connections;
    int failed_requests;
    int successful_requests;
    double network_throughput_mbps;
    
    PerformanceMetrics() 
        : request_latency_ms(0.0), database_query_time_ms(0.0), 
          encryption_time_ms(0.0), memory_usage_mb(0.0), cpu_usage_percent(0.0),
          active_connections(0), failed_requests(0), successful_requests(0),
          network_throughput_mbps(0.0) {}
    
    void update_average(const PerformanceMetrics& new_metrics, double alpha = 0.1) {
        request_latency_ms = alpha * new_metrics.request_latency_ms + (1 - alpha) * request_latency_ms;
        database_query_time_ms = alpha * new_metrics.database_query_time_ms + (1 - alpha) * database_query_time_ms;
        encryption_time_ms = alpha * new_metrics.encryption_time_ms + (1 - alpha) * encryption_time_ms;
        memory_usage_mb = alpha * new_metrics.memory_usage_mb + (1 - alpha) * memory_usage_mb;
        cpu_usage_percent = alpha * new_metrics.cpu_usage_percent + (1 - alpha) * cpu_usage_percent;
        active_connections = new_metrics.active_connections;
        failed_requests += new_metrics.failed_requests;
        successful_requests += new_metrics.successful_requests;
        network_throughput_mbps = alpha * new_metrics.network_throughput_mbps + (1 - alpha) * network_throughput_mbps;
    }
    
    std::string to_json() const {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2);
        ss << "{"
           << "\"request_latency_ms\":" << request_latency_ms << ","
           << "\"database_query_time_ms\":" << database_query_time_ms << ","
           << "\"encryption_time_ms\":" << encryption_time_ms << ","
           << "\"memory_usage_mb\":" << memory_usage_mb << ","
           << "\"cpu_usage_percent\":" << cpu_usage_percent << ","
           << "\"active_connections\":" << active_connections << ","
           << "\"failed_requests\":" << failed_requests << ","
           << "\"successful_requests\":" << successful_requests << ","
           << "\"network_throughput_mbps\":" << network_throughput_mbps << ","
           << "\"success_rate\":" << (successful_requests > 0 ? 
                (double)successful_requests / (successful_requests + failed_requests) * 100 : 0)
           << "}";
        return ss.str();
    }
};

class PerformanceAnalyzer {
private:
    std::atomic<bool> running;
    std::thread analysis_thread;
    std::mutex metrics_mutex;
    std::queue<PerformanceMetrics> metrics_queue;
    std::condition_variable metrics_cv;
    
    PerformanceMetrics current_metrics;
    std::vector<PerformanceMetrics> metrics_history;
    size_t max_history_size;
    
    std::map<std::string, std::vector<double>> anomaly_detection_cache;
    std::unordered_map<std::string, double> performance_baselines;
    
public:
    PerformanceAnalyzer(size_t history_size = 1000) 
        : running(false), max_history_size(history_size) {
        initialize_baselines();
    }
    
    ~PerformanceAnalyzer() {
        stop();
    }
    
    void start() {
        running = true;
        analysis_thread = std::thread(&PerformanceAnalyzer::analysis_loop, this);
        std::cout << "🚀 Performance Analyzer started\n";
    }
    
    void stop() {
        running = false;
        metrics_cv.notify_all();
        if (analysis_thread.joinable()) {
            analysis_thread.join();
        }
        std::cout << "🛑 Performance Analyzer stopped\n";
    }
    
    void add_metrics(const PerformanceMetrics& metrics) {
        std::lock_guard<std::mutex> lock(metrics_mutex);
        metrics_queue.push(metrics);
        metrics_cv.notify_one();
    }
    
    PerformanceMetrics get_current_metrics() const {
        std::lock_guard<std::mutex> lock(metrics_mutex);
        return current_metrics;
    }
    
    std::vector<PerformanceMetrics> get_metrics_history() const {
        std::lock_guard<std::mutex> lock(metrics_mutex);
        return metrics_history;
    }
    
private:
    void analysis_loop() {
        while (running) {
            std::unique_lock<std::mutex> lock(metrics_mutex);
            metrics_cv.wait_for(lock, std::chrono::seconds(1), 
                [this]() { return !metrics_queue.empty() || !running; });
            
            if (!running) break;
            
            if (!metrics_queue.empty()) {
                PerformanceMetrics new_metrics = metrics_queue.front();
                metrics_queue.pop();
                lock.unlock();
                
                process_metrics(new_metrics);
                detect_anomalies(new_metrics);
                optimize_performance(new_metrics);
                generate_report(new_metrics);
            } else {
                lock.unlock();
                // Periodic system check even without new metrics
                perform_system_health_check();
            }
        }
    }
    
    void process_metrics(const PerformanceMetrics& new_metrics) {
        std::lock_guard<std::mutex> lock(metrics_mutex);
        
        // Update current metrics with exponential moving average
        current_metrics.update_average(new_metrics);
        
        // Add to history
        metrics_history.push_back(new_metrics);
        if (metrics_history.size() > max_history_size) {
            metrics_history.erase(metrics_history.begin());
        }
        
        // Update baseline if needed
        update_performance_baseline(new_metrics);
    }
    
    void detect_anomalies(const PerformanceMetrics& metrics) {
        // Check for latency anomalies
        if (metrics.request_latency_ms > performance_baselines["request_latency"] * 2.5) {
            log_anomaly("High latency detected", metrics.request_latency_ms);
            trigger_performance_alert("LATENCY_SPIKE", metrics.request_latency_ms);
        }
        
        // Check for memory anomalies
        if (metrics.memory_usage_mb > performance_baselines["memory_usage"] * 1.8) {
            log_anomaly("High memory usage", metrics.memory_usage_mb);
            trigger_performance_alert("MEMORY_LEAK", metrics.memory_usage_mb);
        }
        
        // Check for CPU anomalies
        if (metrics.cpu_usage_percent > performance_baselines["cpu_usage"] * 2.0) {
            log_anomaly("High CPU usage", metrics.cpu_usage_percent);
            trigger_performance_alert("CPU_SPIKE", metrics.cpu_usage_percent);
        }
        
        // Check for error rate anomalies
        double error_rate = metrics.failed_requests > 0 ? 
            (double)metrics.failed_requests / (metrics.successful_requests + metrics.failed_requests) : 0;
        
        if (error_rate > 0.05) { // 5% error rate threshold
            log_anomaly("High error rate", error_rate * 100);
            trigger_performance_alert("ERROR_RATE_HIGH", error_rate * 100);
        }
        
        // Statistical anomaly detection using Z-score
        detect_statistical_anomalies(metrics);
    }
    
    void detect_statistical_anomalies(const PerformanceMetrics& metrics) {
        // Simple Z-score based anomaly detection
        std::vector<double> latencies;
        for (const auto& hist : metrics_history) {
            latencies.push_back(hist.request_latency_ms);
        }
        
        if (latencies.size() > 10) {
            double mean = calculate_mean(latencies);
            double stddev = calculate_stddev(latencies, mean);
            
            if (stddev > 0) {
                double z_score = (metrics.request_latency_ms - mean) / stddev;
                
                if (std::abs(z_score) > 3.0) { // 3 sigma rule
                    log_anomaly("Statistical anomaly detected (Z-score: " + 
                               std::to_string(z_score) + ")", metrics.request_latency_ms);
                }
            }
        }
    }
    
    void optimize_performance(const PerformanceMetrics& metrics) {
        static int optimization_counter = 0;
        optimization_counter++;
        
        // Optimize database connection pool
        if (metrics.database_query_time_ms > 50.0) {
            suggest_optimization("Consider increasing database connection pool size");
        }
        
        // Optimize encryption operations
        if (metrics.encryption_time_ms > 10.0) {
            suggest_optimization("Consider implementing encryption caching");
        }
        
        // Optimize memory usage
        if (metrics.memory_usage_mb > 512.0) { // 512MB threshold
            suggest_optimization("Consider implementing memory pooling");
        }
        
        // Every 100 metrics, run deep optimization analysis
        if (optimization_counter % 100 == 0) {
            run_deep_optimization_analysis();
        }
    }
    
    void run_deep_optimization_analysis() {
        HighResolutionTimer timer;
        
        // Analyze metrics trends
        std::vector<double> latencies;
        std::vector<double> memory_usage;
        
        for (const auto& metric : metrics_history) {
            latencies.push_back(metric.request_latency_ms);
            memory_usage.push_back(metric.memory_usage_mb);
        }
        
        // Calculate trends using linear regression
        auto latency_trend = calculate_linear_trend(latencies);
        auto memory_trend = calculate_linear_trend(memory_usage);
        
        // Generate optimization recommendations
        std::vector<std::string> recommendations;
        
        if (latency_trend.slope > 0.1) {
            recommendations.push_back("⚠️  Latency is increasing. Consider query optimization.");
        }
        
        if (memory_trend.slope > 5.0) {
            recommendations.push_back("⚠️  Memory usage is increasing rapidly. Check for leaks.");
        }
        
        // Calculate correlation between metrics
        double correlation = calculate_correlation(latencies, memory_usage);
        if (correlation > 0.7) {
            recommendations.push_back("📊 High correlation between latency and memory usage");
        }
        
        // Save analysis report
        save_optimization_report(recommendations, timer.elapsed_milliseconds());
    }
    
    void generate_report(const PerformanceMetrics& metrics) {
        static int report_counter = 0;
        report_counter++;
        
        // Generate report every 60 metrics (approx once per minute)
        if (report_counter % 60 == 0) {
            std::stringstream report;
            report << "📊 PERFORMANCE REPORT 📊\n";
            report << "Timestamp: " << get_current_timestamp() << "\n";
            report << "Avg Latency: " << metrics.request_latency_ms << "ms\n";
            report << "Avg DB Query: " << metrics.database_query_time_ms << "ms\n";
            report << "Memory Usage: " << metrics.memory_usage_mb << "MB\n";
            report << "CPU Usage: " << metrics.cpu_usage_percent << "%\n";
            report << "Active Connections: " << metrics.active_connections << "\n";
            report << "Success Rate: " 
                   << (metrics.successful_requests > 0 ? 
                      (double)metrics.successful_requests / (metrics.successful_requests + metrics.failed_requests) * 100 : 0)
                   << "%\n";
            
            // Save report to file
            save_report_to_file(report.str());
            
            // Reset counters
            report_counter = 0;
        }
    }
    
    void perform_system_health_check() {
        // Simulate system resource checks
        PerformanceMetrics system_metrics;
        system_metrics.memory_usage_mb = get_system_memory_usage();
        system_metrics.cpu_usage_percent = get_system_cpu_usage();
        
        // Check for system-level issues
        if (system_metrics.memory_usage_mb > 800.0) {
            log_anomaly("System memory critical", system_metrics.memory_usage_mb);
        }
        
        if (system_metrics.cpu_usage_percent > 90.0) {
            log_anomaly("System CPU critical", system_metrics.cpu_usage_percent);
        }
    }
    
    void initialize_baselines() {
        performance_baselines["request_latency"] = 50.0;  // 50ms
        performance_baselines["database_query_time"] = 20.0; // 20ms
        performance_baselines["encryption_time"] = 5.0;   // 5ms
        performance_baselines["memory_usage"] = 256.0;   // 256MB
        performance_baselines["cpu_usage"] = 30.0;       // 30%
    }
    
    void update_performance_baseline(const PerformanceMetrics& metrics) {
        // Update baselines based on 95th percentile of historical data
        for (auto& [key, value] : performance_baselines) {
            std::vector<double> values;
            for (const auto& hist : metrics_history) {
                if (key == "request_latency") values.push_back(hist.request_latency_ms);
                else if (key == "database_query_time") values.push_back(hist.database_query_time_ms);
                else if (key == "encryption_time") values.push_back(hist.encryption_time_ms);
                else if (key == "memory_usage") values.push_back(hist.memory_usage_mb);
                else if (key == "cpu_usage") values.push_back(hist.cpu_usage_percent);
            }
            
            if (values.size() > 100) {
                std::sort(values.begin(), values.end());
                size_t percentile_index = values.size() * 0.95;
                value = values[percentile_index];
            }
        }
    }
    
    // Utility functions
    double calculate_mean(const std::vector<double>& values) {
        double sum = 0.0;
        for (double val : values) sum += val;
        return sum / values.size();
    }
    
    double calculate_stddev(const std::vector<double>& values, double mean) {
        double variance = 0.0;
        for (double val : values) {
            variance += std::pow(val - mean, 2);
        }
        return std::sqrt(variance / values.size());
    }
    
    struct TrendResult {
        double slope;
        double intercept;
        double r_squared;
    };
    
    TrendResult calculate_linear_trend(const std::vector<double>& values) {
        TrendResult result = {0.0, 0.0, 0.0};
        if (values.size() < 2) return result;
        
        double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;
        int n = values.size();
        
        for (int i = 0; i < n; i++) {
            sum_x += i;
            sum_y += values[i];
            sum_xy += i * values[i];
            sum_x2 += i * i;
        }
        
        double mean_x = sum_x / n;
        double mean_y = sum_y / n;
        
        result.slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        result.intercept = mean_y - result.slope * mean_x;
        
        // Calculate R-squared
        double ss_total = 0.0, ss_residual = 0.0;
        for (int i = 0; i < n; i++) {
            double y_pred = result.slope * i + result.intercept;
            ss_total += std::pow(values[i] - mean_y, 2);
            ss_residual += std::pow(values[i] - y_pred, 2);
        }
        
        result.r_squared = 1.0 - (ss_residual / ss_total);
        return result;
    }
    
    double calculate_correlation(const std::vector<double>& x, const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) return 0.0;
        
        double mean_x = calculate_mean(x);
        double mean_y = calculate_mean(y);
        
        double numerator = 0.0, denom_x = 0.0, denom_y = 0.0;
        
        for (size_t i = 0; i < x.size(); i++) {
            numerator += (x[i] - mean_x) * (y[i] - mean_y);
            denom_x += std::pow(x[i] - mean_x, 2);
            denom_y += std::pow(y[i] - mean_y, 2);
        }
        
        return numerator / std::sqrt(denom_x * denom_y);
    }
    
    void log_anomaly(const std::string& message, double value) {
        std::string timestamp = get_current_timestamp();
        std::cout << "🚨 [" << timestamp << "] ANOMALY: " << message 
                  << " (Value: " << value << ")\n";
        
        // Log to file
        std::ofstream log_file("anomalies.log", std::ios::app);
        if (log_file.is_open()) {
            log_file << "[" << timestamp << "] " << message << " | Value: " << value << "\n";
            log_file.close();
        }
    }
    
    void trigger_performance_alert(const std::string& alert_type, double value) {
        // In production, this would trigger actual alerts (email, Slack, etc.)
        std::cout << "🔔 PERFORMANCE ALERT: " << alert_type << " | Value: " << value << "\n";
    }
    
    void suggest_optimization(const std::string& suggestion) {
        std::cout << "💡 OPTIMIZATION SUGGESTION: " << suggestion << "\n";
    }
    
    void save_optimization_report(const std::vector<std::string>& recommendations, double analysis_time) {
        std::ofstream report_file("optimization_report_" + get_current_timestamp() + ".txt");
        if (report_file.is_open()) {
            report_file << "Optimization Analysis Report\n";
            report_file << "Generated: " << get_current_timestamp() << "\n";
            report_file << "Analysis Time: " << analysis_time << "ms\n\n";
            report_file << "Recommendations:\n";
            
            for (const auto& rec : recommendations) {
                report_file << "• " << rec << "\n";
            }
            
            report_file.close();
        }
    }
    
    void save_report_to_file(const std::string& report) {
        std::ofstream report_file("performance_reports.log", std::ios::app);
        if (report_file.is_open()) {
            report_file << report << "\n---\n";
            report_file.close();
        }
    }
    
    std::string get_current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    // Mock system functions (would be real in production)
    double get_system_memory_usage() {
        // Simulate memory usage
        static double memory = 256.0;
        memory += (rand() % 10 - 5) * 0.1; // Random walk
        return std::max(100.0, std::min(1000.0, memory));
    }
    
    double get_system_cpu_usage() {
        // Simulate CPU usage
        static double cpu = 30.0;
        cpu += (rand() % 20 - 10) * 0.1; // Random walk
        return std::max(5.0, std::min(100.0, cpu));
    }
};
