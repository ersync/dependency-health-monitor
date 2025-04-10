#!/usr/bin/env ruby
# dep_health.rb - Monitor dependencies across repositories

require 'octokit'
require 'json'
require 'open3'
require 'terminal-table'
require 'colorize'
require 'optparse'

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
    
    @client = Octokit::Client.new(access_token: @token)
    @client.auto_paginate = true
  end
  
  def scan
    repos = fetch_repositories
    puts "Found #{repos.count} repositories. Scanning up to #{@options[:max_repos]}...".yellow
    
    results = []
    repos.take(@options[:max_repos]).each do |repo|
      puts "Scanning #{repo.full_name}...".cyan if @options[:verbose]
      result = scan_repository(repo)
      results << result if result
    end
    
    display_results(results)
    write_report(results) if @options[:output]
  end
  
  private
  
  def fetch_repositories
    if @options[:repo]
      [@client.repository(@options[:repo])]
    elsif @options[:org]
      @client.organization_repositories(@options[:org])
    else
      @client.repositories(@options[:user] || @client.user.login)
    end
  end
  
  def scan_repository(repo)
    # Clone repository to temporary directory
    temp_dir = "temp_#{Time.now.to_i}"
    clone_url = "https://#{@token}@github.com/#{repo.full_name}.git"
    
    system("git clone --depth 1 #{clone_url} #{temp_dir} > /dev/null 2>&1")
    return nil unless File.directory?(temp_dir)
    
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
    
    # Cleanup
    system("rm -rf #{temp_dir}")
    result
  end
  
  def scan_npm_dependencies(result)
    # Run npm audit
    stdout, stderr, status = Open3.capture3("npm audit --json 2>/dev/null")
    if status.success? && !stdout.empty?
      begin
        audit = JSON.parse(stdout)
        result[:vulnerabilities] = audit["metadata"]["vulnerabilities"]["total"]
        
        # Add top issues
        audit["advisories"]&.each do |_, adv|
          result[:issues] << {
            type: :vulnerability,
            severity: adv["severity"],
            package: adv["module_name"],
            message: adv["title"]
          }
        end
      rescue JSON::ParserError
        # Handle parse errors
      end
    end
    
    # Check outdated packages
    stdout, stderr, status = Open3.capture3("npm outdated --json 2>/dev/null")
    if status.success? && !stdout.empty?
      begin
        outdated = JSON.parse(stdout)
        result[:outdated] = outdated.keys.count
        
        # Add top outdated packages
        outdated.each do |pkg, info|
          result[:issues] << {
            type: :outdated,
            package: pkg,
            current: info["current"],
            latest: info["latest"],
            message: "Update from #{info["current"]} to #{info["latest"]}"
          }
        end
      rescue JSON::ParserError
        # Handle parse errors
      end
    end
  end
  
  def scan_ruby_dependencies(result)
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
      rescue JSON::ParserError
        # Handle parse errors
      end
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
    end
  end
  
  def scan_python_dependencies(result)
    # Create virtual environment for safety checks
    system("python -m venv .venv > /dev/null 2>&1")
    system(".venv/bin/pip install -r requirements.txt > /dev/null 2>&1")
    system(".venv/bin/pip install safety > /dev/null 2>&1")
    
    # Run safety check
    stdout, stderr, status = Open3.capture3(".venv/bin/safety check --json 2>/dev/null")
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
      rescue JSON::ParserError
        # Handle parse errors
      end
    end
    
    # Check outdated packages
    stdout, stderr, status = Open3.capture3(".venv/bin/pip list --outdated --format=json 2>/dev/null")
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
      rescue JSON::ParserError
        # Handle parse errors
      end
    end
  end
  
  def display_results(results)
    summary_table = Terminal::Table.new do |t|
      t << ['Repository', 'Language', 'Vulnerabilities', 'Outdated']
      t.add_separator
      
      results.each do |result|
        vulnerabilities = result[:vulnerabilities] > 0 ? result[:vulnerabilities].to_s.red : result[:vulnerabilities].to_s.green
        outdated = result[:outdated] > 0 ? result[:outdated].to_s.yellow : result[:outdated].to_s.green
        
        t << [result[:name], result[:language], vulnerabilities, outdated]
      end
    end
    
    puts "Dependency Health Summary".bold
    puts summary_table
    
    # Show detailed issues for repositories with problems
    results.each do |result|
      next if result[:issues].empty?
      
      puts "\nIssues in #{result[:name]}:".bold
      
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
    end
  end
  
  def write_report(results)
    File.open(@options[:output], 'w') do |file|
      file.puts JSON.pretty_generate({
        scan_date: Time.now.iso8601,
        repositories: results.count,
        total_vulnerabilities: results.sum { |r| r[:vulnerabilities] },
        total_outdated: results.sum { |r| r[:outdated] },
        results: results
      })
    end
    puts "Report written to #{@options[:output]}".green
  end
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
end.parse!

# Get token from environment if not provided
token = options.delete(:token) || ENV['GITHUB_TOKEN']

if token.nil?
  puts "Error: GitHub token required. Use --token option or set GITHUB_TOKEN environment variable.".red
  exit 1
end

monitor = DependencyHealthMonitor.new(token, options)
monitor.scan