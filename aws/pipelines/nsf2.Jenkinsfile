pipeline {
    agent { label "jenkins" }
    options {
        buildDiscarder(logRotator(numToKeepStr: '7'))
    }
    environment {
        // Override these three in Jenkins' global / folder env, or edit here.
        NSF_REPO_URL    = "${env.NSF_REPO_URL ?: 'https://github.com/SafeInsights/nsf-critical-controls-set.git'}"
        NSF_REPO_CRED   = "${env.NSF_REPO_CRED ?: 'github-pat'}"
        NSF_NOTIFY_TO   = "${env.NSF_NOTIFY_TO ?: 'security@safeinsights.org'}"
    }
    triggers {
        // Run daily at 12:15am CST
        cron('15 6 * * *')
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: "${env.NSF_REPO_URL}",
                    credentialsId: "${env.NSF_REPO_CRED}"
            }
        }
        stage('Setup Python') {
            steps {
                sh '''
                    cd aws
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install --quiet -r requirements.txt
                '''
            }
        }
        stage('NSF2: Phishing-resistant MFA for Remote Access') {
            steps {
                sh '''
                    cd aws
                    . venv/bin/activate
                    mkdir -p ${WORKSPACE}/output
                    python3 -m audits.nsf2 \
                        --output-dir ${WORKSPACE}/output
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'output/*', allowEmptyArchive: true
        }
        failure {
            emailext(
                to: "${env.NSF_NOTIFY_TO}",
                subject: "NSF2 Audit Failed - Build ${env.BUILD_NUMBER}",
                body: "NSF2 Phishing-resistant MFA for Remote Access audit failed.\n\nCheck ${env.BUILD_URL} for details."
            )
        }
    }
}
