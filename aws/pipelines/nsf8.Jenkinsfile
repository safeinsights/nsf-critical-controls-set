pipeline {
    agent { label "jenkins" }
    options {
        buildDiscarder(logRotator(numToKeepStr: '7'))
    }
    triggers {
        // Run daily at 1:45am CST
        cron('45 7 * * *')
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
        stage('NSF8: Regular Tests of Backup Integrity') {
            steps {
                sh '''
                    cd aws
                    . venv/bin/activate
                    mkdir -p ${WORKSPACE}/output
                    python3 -m audits.nsf8 \
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
                subject: "NSF8 Audit Failed - Build ${env.BUILD_NUMBER}",
                body: "NSF8 Regular Tests of Backup Integrity audit failed.\n\nCheck ${env.BUILD_URL} for details."
            )
        }
    }
}
