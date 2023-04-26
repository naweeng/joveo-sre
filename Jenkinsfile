pipeline {
  agent any
  
  parameters {
    string(name: 'Target', defaultValue: '', description: 'Enter the target URL for ZAP scan')
  }
  
  stages {
    stage('ZAP Scan') {
      steps {
        sh "docker run -i --rm -v /var/lib/jenkins/zaptest:/zap/wrk owasp/zap2docker-stable:latest zap-api-scan.py -t ${params.Target} -f openapi -r 'report_$(date +%Y-%m-%d).html' -J 'report_$(date +%Y-%m-%d).json'"
      }
    }
    
    stage('Copy report to S3') {
      steps {
          sh "aws s3 cp /var/lib/jenkins/zaptest/report_$(date +%Y-%m-%d).html s3://sre-joveo/zap_reports/ --profile joveo-prod"
        
      }
    }
    
    stage('Login to ECR') {
      steps {
 
          sh "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 485239875118.dkr.ecr.us-east-1.amazonaws.com"
        
      }
    }
    
    stage('Pull and run ZAP report image') {
      steps {
        sh "docker pull 485239875118.dkr.ecr.us-east-1.amazonaws.com/sre/zap-report:latest"
        sh "docker run -e alert_type='High' -i --rm -v /var/lib/jenkins/zaptest:/app 485239875118.dkr.ecr.us-east-1.amazonaws.com/sre/zap-report:latest"
      }
    }
    
    stage('Clean up') {
      steps {
        sh "rm /var/lib/jenkins/zaptest/report_*"
      }
    }
  }
}
