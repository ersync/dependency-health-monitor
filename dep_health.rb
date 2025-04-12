#!/usr/bin/env ruby
# dep_health.rb - Monitor dependencies across repositories

require 'octokit'
require 'json'
require 'open3'
require 'terminal-table'
require 'colorize'
require 'optparse'
require 'logger'

# Suppress Faraday warning by installing the gem if not already installed
begin
  require 'faraday-retry'
rescue LoadError
  system("gem install faraday-retry --no-document")
  Gem.clear_paths
  begin
    require 'faraday-retry'
  rescue LoadError
    # Continue even if we can't load it
  end
end

class DependencyHealthMonitor
  def initialize(token, options = {})
    @token = token
    @options = {
      org: nil,
      user: nil,
      repo: nil,
      max_repos: 10,
      verbose: false
    }.merge(options)
    
    # Initialize logger
    @logger = Logger.new($stdout)
    @logger.level = @options[:verbose] ? Logger::DEBUG : Logger::INFO
    @logger.formatter = proc do |severity, datetime, progname, msg|
      case severity
      when "ERROR", "FATAL"
        "#{msg}".red + "\n"
      when "WARN"
        "#{msg}".yellow + "\n"
      when "DEBUG"
        "#{msg}".cyan + "\n"
      else
        "#{msg}\n"
      end
    end
    
    begin
      @client = Octokit::Client.new(access_token: @token)
      @client.auto_paginate = true
      # Verify token works by fetching user info
      @client.user
    rescue Octokit::Unauthorized
      @logger.fatal "Error: Invalid GitHub token. Please check your token and try again."
      exit 1
    rescue Octokit::Error => e
      @logger.fatal "GitHub API Error: #{e.message}"
      exit 1
    end
  end
  
  def scan
    begin
      repos = fetch_repositories
      repo_count = repos.count
      max_scan = [@options[:max_repos], repo_count].min
      
      repo_text = repo_count == 1 ? "repository" : "repositories"
      scan_text = max_scan == 1 ? "repository" : "repositories"
      
      @logger.info "Found #{repo_count} #{repo_text}. Scanning up to #{max_scan} #{scan_text}..."
      
      results = []
      spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
      spinner_thread = nil
      
      if !@options[:verbose]
        # Start spinner in a separate thread
        spinner_thread = Thread.new do
          i = 0
          while true
            scan_text = max_scan == 1 ? "repository" : "repositories"
            print "\r#{spinner_chars[i % spinner_chars.length]} Scanning #{scan_text}... "
            sleep 0.1
            i += 1
          end
        end
      end
      
      repos.take(max_scan).each_with_index do |repo, index|
        @logger.debug "Scanning #{repo.full_name} (#{index+1}/#{max_scan})..."
        result = scan_repository(repo)
        results << result if result
      end
      
      # Stop spinner
      if spinner_thread
        spinner_thread.kill
        print "\r" + " " * 50 + "\r" # Clear the spinner line
      end
      
      if results.empty?
        @logger.warn "No repositories were successfully scanned."
        return
      end
      
      display_results(results)
      write_report(results) if @options[:output]
      
    rescue Interrupt
      # Stop spinner if it's running
      if spinner_thread
        spinner_thread.kill
        print "\r" + " " * 50 + "\r" # Clear the spinner line
      end
      
      @logger.warn "\nScan interrupted. Processing results collected so far..."
      display_results(results) if defined?(results) && !results.empty?
      write_report(results) if defined?(results) && !results.empty? && @options[:output]
      exit 1
    rescue StandardError => e
      # Stop spinner if it's running
      if spinner_thread
        spinner_thread.kill
        print "\r" + " " * 50 + "\r" # Clear the spinner line
      end
      
      @logger.fatal "Unexpected error: #{e.message}"
      @logger.debug e.backtrace.join("\n") if @options[:verbose]
      exit 1
    end
  end
  
  private
  
  def fetch_repositories
    begin
      if @options[:repo]
        [@client.repository(@options[:repo])]
      elsif @options[:org]
        @client.organization_repositories(@options[:org])
      else
        @client.repositories(@options[:user] || @client.user.login)
      end
    rescue Octokit::NotFound
      target = @options[:repo] || @options[:org] || @options[:user] || "default user"
      @logger.fatal "Error: #{target} not found."
      exit 1
    end
  end
  
  def scan_repository(repo)
    # Clone repository to temporary directory
    temp_dir = "temp_#{Time.now.to_i}_#{rand(1000)}"
    clone_url = "https://#{@token}@github.com/#{repo.full_name}.git"
    
    begin
      # Check if git is installed
      unless system("which git > /dev/null 2>&1")
        @logger.error "Git is not installed or not in PATH. Please install git."
        return nil
      end
      
      clone_output, status = Open3.capture2e("git clone --depth 1 #{clone_url} #{temp_dir}")
      unless status.success?
        @logger.error "Failed to clone #{repo.full_name}: #{clone_output.strip}"
        return nil
      end
      
      unless File.directory?(temp_dir)
        @logger.error "Failed to create directory for #{repo.full_name}"
        return nil
      end
      
      result = {
        name: repo.full_name,
        language: repo.language,
        issues: [],
        vulnerabilities: 0,
        outdated: 0,
        deprecated: 0
      }
      
      # Check package managers based on files
      Dir.chdir(temp_dir) do
        # NPM/Yarn
        if File.exist?('package.json')
          result[:package_manager] = 'npm'
          scan_npm_dependencies(result)
        end
        
        # Ruby/Bundler
        if File.exist?('Gemfile')
          result[:package_manager] = 'bundler'
          scan_ruby_dependencies(result)
        end
        
        # Python/Pip
        if File.exist?('requirements.txt')
          result[:package_manager] = 'pip'
          scan_python_dependencies(result)
        end
      end
      
      # Calculate health score
      result[:health_score] = calculate_health_score(result)
      return result
      
    rescue StandardError => e
      @logger.error "Error scanning #{repo.full_name}: #{e.message}"
      return nil
    ensure
      # Cleanup
      if File.directory?(temp_dir)
        begin
          FileUtils.rm_rf(temp_dir)
        rescue StandardError => e
          @logger.warn "Failed to clean up #{temp_dir}: #{e.message}"
        end
      end
    end
  end
  
  def calculate_health_score(result)
    # Base score starts at 100
    score = 100
    
    # Deduct points for vulnerabilities based on severity
    result[:issues].each do |issue|
      if issue[:type] == :vulnerability
        case issue[:severity]&.downcase
        when "critical" then score -= 15
        when "high" then score -= 10
        when "medium" then score -= 5
        when "low" then score -= 2
        else score -= 3 # unknown severity
        end
      end
    end
    
    # Deduct for outdated packages (less impact than vulnerabilities)
    outdated_penalty = result[:outdated] * 1.5
    score -= [outdated_penalty, 40].min # Cap at 40 points max for outdated
    
    # Deduct more for severely outdated packages (major version differences)
    result[:issues].each do |issue|
      if issue[:type] == :outdated && issue[:current] && issue[:latest]
        begin
          current_parts = issue[:current].split('.')
          latest_parts = issue[:latest].split('.')
          
          # Major version difference
          if latest_parts[0].to_i > current_parts[0].to_i
            score -= 3
          end
        rescue StandardError => e
          # Skip this check if version parsing fails
          @logger.debug "Could not parse version for #{issue[:package]}: #{e.message}" if @options[:verbose]
        end
      end
    end
    
    # Ensure score stays within 0-100 range
    [score.round, 0].max
  end
  
  def scan_npm_dependencies(result)
    # Check if npm is installed
    unless system("which npm > /dev/null 2>&1")
      @logger.debug "npm not installed, skipping npm dependency scan"
      return
    end
  
    # Check if package.json exists and has dependencies
    unless File.exist?('package.json')
      @logger.debug "No package.json found, skipping npm scan"
      return
    end
    
    # Try to install dependencies if needed
    begin
      @logger.debug "Installing npm dependencies..."
      Open3.capture2e("npm install --no-fund --no-audit --silent")
    rescue StandardError => e
      @logger.debug "Could not install npm dependencies: #{e.message}"
    end
  
    # Run npm audit
    @logger.debug "Running npm audit..."
    stdout, stderr, status = Open3.capture3("npm audit --json 2>/dev/null")
    if !stderr.empty? && @options[:verbose]
      @logger.debug "npm audit stderr: #{stderr}"
    end
    
    if !stdout.empty?
      begin
        audit = JSON.parse(stdout)
        result[:vulnerabilities] = audit["metadata"]["vulnerabilities"]["total"] rescue 0
        
        # Add top issues
        if audit["advisories"]
          audit["advisories"].each do |_, adv|
            result[:issues] << {
              type: :vulnerability,
              severity: adv["severity"],
              package: adv["module_name"],
              message: adv["title"]
            }
          end
        end
      rescue JSON::ParserError => e
        @logger.debug "Failed to parse npm audit output: #{e.message}"
      end
    end
    
    # Check outdated packages
    @logger.debug "Running npm outdated..."
    stdout, stderr, status = Open3.capture3("npm outdated --json 2>/dev/null")
    if !stderr.empty? && @options[:verbose]
      @logger.debug "npm outdated stderr: #{stderr}"
    end
    
    if !stdout.empty? && stdout != "{}\n"
      begin
        outdated = JSON.parse(stdout)
        result[:outdated] = outdated.keys.count
        
        # Add top outdated packages
        outdated.each do |pkg, info|
          current_version = info["current"] || "not installed"
          latest_version = info["latest"] || "unknown"
          
          result[:issues] << {
            type: :outdated,
            package: pkg,
            current: current_version,
            latest: latest_version,
            message: "Update from #{current_version} to #{latest_version}"
          }
        end
      rescue JSON::ParserError => e
        @logger.debug "Failed to parse npm outdated output: #{e.message}"
        @logger.debug "Raw output: #{stdout}" if @options[:verbose]
      end
    end
  end
  
  def scan_ruby_dependencies(result)
    # Check if bundle is installed
    unless system("which bundle > /dev/null 2>&1")
      @logger.debug "bundler not installed, skipping Ruby dependency scan"
      return
    end
    
    # Install dependencies if needed
    begin
      Open3.capture2e("bundle install --quiet")
    rescue StandardError => e
      @logger.debug "Could not install Ruby dependencies: #{e.message}"
      return
    end
    
    # Run bundle audit
    stdout, stderr, status = Open3.capture3("bundle audit check --format json 2>/dev/null")
    if status.success? && !stdout.empty?
      begin
        audit = JSON.parse(stdout)
        result[:vulnerabilities] = audit.count
        
        # Add vulnerabilities
        audit.each do |vuln|
          result[:issues] << {
            type: :vulnerability,
            severity: vuln["criticality"] || "unknown",
            package: vuln["gem"],
            message: vuln["advisory"]["title"]
          }
        end
      rescue JSON::ParserError => e
        @logger.debug "Failed to parse bundle audit output: #{e.message}"
      end
    elsif !stderr.empty? && @options[:verbose]
      @logger.debug "bundle audit stderr: #{stderr}"
    end
    
    # Check outdated gems
    stdout, stderr, status = Open3.capture3("bundle outdated --parseable 2>/dev/null")
    if status.success?
      outdated = stdout.split("\n")
      result[:outdated] = outdated.count
      
      # Add outdated gems
      outdated.take(5).each do |line|
        if line =~ /(\S+) \((.+) < (.+)\)/
          result[:issues] << {
            type: :outdated,
            package: $1,
            current: $2,
            latest: $3,
            message: "Update from #{$2} to #{$3}"
          }
        end
      end
    elsif !stderr.empty? && @options[:verbose]
      @logger.debug "bundle outdated stderr: #{stderr}"
    end
  end
  
  def scan_python_dependencies(result)
    # Check if python and pip are installed
    unless system("which python3 > /dev/null 2>&1") || system("which python > /dev/null 2>&1")
      @logger.debug "Python not installed, skipping Python dependency scan"
      return
    end
    
    # Create virtual environment for safety checks
    python_cmd = system("which python3 > /dev/null 2>&1") ? "python3" : "python"
    venv_create, status = Open3.capture2e("#{python_cmd} -m venv .venv")
    
    unless status.success?
      @logger.debug "Failed to create Python virtual environment: #{venv_create}"
      return
    end
    
    pip_cmd = File.exist?(".venv/bin/pip") ? ".venv/bin/pip" : ".venv/Scripts/pip"
    
    # Install dependencies
    begin
      install_output, status = Open3.capture2e("#{pip_cmd} install -r requirements.txt")
      unless status.success?
        @logger.debug "Failed to install Python dependencies: #{install_output}"
        return
      end
      
      safety_output, status = Open3.capture2e("#{pip_cmd} install safety")
      unless status.success?
        @logger.debug "Failed to install safety: #{safety_output}"
        return
      end
    rescue StandardError => e
      @logger.debug "Error during Python dependency installation: #{e.message}"
      return
    end
    
    # Run safety check
    safety_cmd = File.exist?(".venv/bin/safety") ? ".venv/bin/safety" : ".venv/Scripts/safety"
    stdout, stderr, status = Open3.capture3("#{safety_cmd} check --json 2>/dev/null")
    
    if status.success? && !stdout.empty?
      begin
        safety = JSON.parse(stdout)
        result[:vulnerabilities] = safety["vulnerabilities"].count
        
        # Add vulnerabilities
        safety["vulnerabilities"].each do |vuln|
          result[:issues] << {
            type: :vulnerability,
            severity: vuln["severity"] || "unknown",
            package: vuln["package_name"],
            message: vuln["advisory"]
          }
        end
      rescue JSON::ParserError => e
        @logger.debug "Failed to parse safety check output: #{e.message}"
      end
    elsif !stderr.empty? && @options[:verbose]
      @logger.debug "safety check stderr: #{stderr}"
    end
    
    # Check outdated packages
    stdout, stderr, status = Open3.capture3("#{pip_cmd} list --outdated --format=json 2>/dev/null")
    if status.success? && !stdout.empty?
      begin
        outdated = JSON.parse(stdout)
        result[:outdated] = outdated.count
        
        # Add outdated packages
        outdated.take(5).each do |pkg|
          result[:issues] << {
            type: :outdated,
            package: pkg["name"],
            current: pkg["version"],
            latest: pkg["latest_version"],
            message: "Update from #{pkg["version"]} to #{pkg["latest_version"]}"
          }
        end
      rescue JSON::ParserError => e
        @logger.debug "Failed to parse pip outdated output: #{e.message}"
      end
    elsif !stderr.empty? && @options[:verbose]
      @logger.debug "pip list outdated stderr: #{stderr}"
    end
  end
  
  def display_results(results)
    summary_table = Terminal::Table.new do |t|
      t << ['Repository', 'Language', 'Score', 'Vulnerabilities', 'Outdated']
      t.add_separator
      
      results.each do |result|
        vulnerabilities = result[:vulnerabilities] > 0 ? result[:vulnerabilities].to_s.red : result[:vulnerabilities].to_s.green
        outdated = result[:outdated] > 0 ? result[:outdated].to_s.yellow : result[:outdated].to_s.green
        
        # Color the score based on its value
        score_display = case result[:health_score]
                        when 90..100 then result[:health_score].to_s.green
                        when 70..89 then result[:health_score].to_s.yellow
                        else result[:health_score].to_s.red
                        end
        
        t << [result[:name], result[:language], score_display, vulnerabilities, outdated]
      end
    end
    
    puts "\nDependency Health Summary".bold
    puts summary_table
    
    # Show detailed issues for repositories with problems
    results.each do |result|
      next if result[:issues].empty?
      
      puts "\nIssues in #{result[:name]} (Score: #{result[:health_score]})".bold
      
      issues_table = Terminal::Table.new do |t|
        t << ['Type', 'Package', 'Severity', 'Message']
        t.add_separator
        
        result[:issues].take(10).each do |issue|
          type = issue[:type] == :vulnerability ? "Vulnerability".red : "Outdated".yellow
          severity = issue[:severity] || "N/A"
          t << [type, issue[:package], severity, issue[:message]]
        end
      end
      
      puts issues_table
      
      # Show warning if more issues were found than shown
      if result[:issues].length > 10
        puts "... and #{result[:issues].length - 10} more issues.".yellow
      end
    end
  end
  
  def write_report(results)
    begin
      File.open(@options[:output], 'w') do |file|
        file.puts JSON.pretty_generate({
          scan_date: Time.now.iso8601,
          repositories: results.count,
          total_vulnerabilities: results.sum { |r| r[:vulnerabilities] },
          total_outdated: results.sum { |r| r[:outdated] },
          average_health_score: results.empty? ? 0 : (results.sum { |r| r[:health_score] } / results.count).round(2),
          results: results
        })
      end
      @logger.info "Report written to #{@options[:output]}"
    rescue StandardError => e
      @logger.error "Failed to write report: #{e.message}"
    end
  end
end

required_gems = ['octokit', 'json', 'terminal-table', 'colorize']
missing_gems = required_gems.select { |gem| !Gem::Specification.find_all_by_name(gem).any? }

if !missing_gems.empty?
  puts "Installing required dependencies: #{missing_gems.join(', ')}".yellow
  missing_gems.each do |gem|
    system("gem install #{gem} --no-document")
  end
  puts "Dependencies installed. Restarting script...".green
  exec("ruby #{$0} #{ARGV.join(' ')}")
end

# Parse command line options
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: dep_health.rb [options]"
  
  opts.on("-t", "--token TOKEN", "GitHub token") do |t|
    options[:token] = t
  end
  
  opts.on("-u", "--user USERNAME", "GitHub username") do |u|
    options[:user] = u
  end
  
  opts.on("-o", "--org ORGANIZATION", "GitHub organization") do |o|
    options[:org] = o
  end
  
  opts.on("-r", "--repo REPOSITORY", "Single repository (format: owner/repo)") do |r|
    options[:repo] = r
  end
  
  opts.on("-m", "--max MAX", "Maximum repositories to scan") do |m|
    options[:max_repos] = m.to_i
  end
  
  opts.on("-f", "--file FILENAME", "Output JSON report to file") do |f|
    options[:output] = f
  end
  
  opts.on("-v", "--verbose", "Verbose output") do |v|
    options[:verbose] = v
  end
  
  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

# Get token from environment if not provided
token = options.delete(:token) || ENV['GITHUB_TOKEN']

if token.nil?
  puts "Error: GitHub token required. Use --token option or set GITHUB_TOKEN environment variable.".red
  exit 1
end

# Validate that only one target is specified
target_count = [options[:user], options[:org], options[:repo]].compact.count
if target_count > 1
  puts "Error: Please specify only one of --user, --org, or --repo.".red
  exit 1
end

begin
  require 'fileutils'
  monitor = DependencyHealthMonitor.new(token, options)
  monitor.scan
rescue LoadError => e
  puts "Missing dependency: #{e.message}".red
  puts "Please install required gems with: gem install octokit json terminal-table colorize".red
  exit 1
end