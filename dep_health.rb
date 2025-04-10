#!/usr/bin/env ruby
# dep_health.rb - A simple tool to monitor dependencies across 
repositories

require 'octokit'
require 'json'
require 'open3'
require 'fileutils'

class DependencyHealthMonitor
  def initialize(token, repo = nil)
    @token = token
    @repo = repo
    @client = Octokit::Client.new(access_token: @token)
  end
  
  def scan
    if @repo
      # Scan a specific repository
      repo_obj = @client.repository(@repo)
      result = scan_repository(repo_obj)
      display_result(result)
    else
      # Scan user's own repositories
      username = @client.user.login
      puts "Scanning repositories for #{username}..."
      
      repos = @client.repositories(nil, per_page: 5)
      results = []
      
      repos.each do |repo|
        puts "Checking #{repo.full_name}..."
        result = scan_repository(repo)
        results << result if result
      end
      
      display_results(results)
    end
  end
  
  private
  
  def scan_repository(repo)
    # Clone repository to temporary directory
    temp_dir = "temp_#{Time.now.to_i}"
    clone_url = "https://#{@token}@github.com/#{repo.full_name}.git"
    
    system("git clone --depth 1 #{clone_url} #{temp_dir} > /dev/null 
2>&1")
    return nil unless File.directory?(temp_dir)
    
    result = {
      name: repo.full_name,
      language: repo.language,
      package_manager: nil,
      vulnerabilities: 0,
      outdated: 0,
      issues: []
    }
    
    # Check package managers based on files
    Dir.chdir(temp_dir) do
      # NPM/Yarn
      if File.exist?('package.json')
        result[:package_manager] = 'npm'
        check_npm_dependencies(result)
      end
      
      # Ruby/Bundler
      if File.exist?('Gemfile')
        result[:package_manager] = 'bundler'
        check_ruby_dependencies(result)
      end
    end
    
    # Cleanup
    FileUtils.rm_rf(temp_dir)
    result
  end
  
  def check_npm_dependencies(result)
    # Check outdated packages
    stdout, status = Open3.capture2("npm outdated --json 2>/dev/null")
    if status.success? && !stdout.empty?
      begin
        outdated = JSON.parse(stdout)
        result[:outdated] = outdated.keys.count
        
        # Add top outdated packages (limit to 5)
        outdated.keys.take(5).each do |pkg|
          info = outdated[pkg]
          result[:issues] << {
            type: 'outdated',
            package: pkg,
            current: info["current"],
            latest: info["latest"]
          }
        end
      rescue JSON::ParserError
        # Handle parse errors
      end
    end
  end
  
  def check_ruby_dependencies(result)
    # Check outdated gems
    stdout, status = Open3.capture2("bundle outdated --parseable 
2>/dev/null")
    if status.success?
      outdated = stdout.split("\n")
      result[:outdated] = outdated.count
    end
  end
  
  def display_result(result)
    puts "\nResults for #{result[:name]}:"
    puts "Language: #{result[:language]}"
    puts "Package Manager: #{result[:package_manager]}"
    puts "Outdated dependencies: #{result[:outdated]}"
    
    if result[:issues].any?
      puts "\nTop outdated packages:"
      result[:issues].each do |issue|
        puts "- #{issue[:package]}: #{issue[:current]} -> 
#{issue[:latest]}"
      end
    end
  end
  
  def display_results(results)
    puts "\nSummary of repository scans:"
    puts "------------------------"
    
    results.each do |result|
      puts "#{result[:name]} (#{result[:language]}): #{result[:outdated]} 
outdated packages"
    end
    
    # Show detailed results for repositories with issues
    results.select { |r| r[:issues].any? }.each do |result|
      puts "\nOutdated packages in #{result[:name]}:"
      result[:issues].each do |issue|
        puts "- #{issue[:package]}: #{issue[:current]} -> 
#{issue[:latest]}"
      end
    end
  end
end

# Simple command line handling
if ARGV.empty? || ARGV[0] == '--help'
  puts "Usage: dep_health.rb [REPO]"
  puts "  REPO: Optional repository in format owner/repo"
  puts ""
  puts "Environment variables:"
  puts "  GITHUB_TOKEN: Your GitHub personal access token"
  exit 0
end

token = ENV['GITHUB_TOKEN']
if token.nil?
  puts "Error: GitHub token required. Set GITHUB_TOKEN environment 
variable."
  exit 1
end

repo = ARGV[0] unless ARGV.empty?
monitor = DependencyHealthMonitor.new(token, repo)
monitor.scan
