pipeline {
    agent { label "jenkins" }
    options {
        buildDiscarder(logRotator(numToKeepStr: '7'))
    }
    triggers {
        // Run daily at 3:30am CST
        cron('30 9 * * *')
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/SafeInsights/nsf-critical-controls-set.git',
                    credentialsId: 'github-pat'
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
        stage('NSF13: Hardening Standards') {
            steps {
                sh '''
                    cd aws
                    . venv/bin/activate
                    mkdir -p ${WORKSPACE}/output
                    python3 -m audits.nsf13 \
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
                to: 'security@safeinsights.org',
                subject: "NSF13 Audit Failed - Build ${env.BUILD_NUMBER}",
                body: "NSF13 Hardening Standards audit failed.\n\nCheck ${env.BUILD_URL} for details."
            )
        }
    }
}
