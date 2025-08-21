#!/bin/bash

SUNRAYSRVR_MAIN_VERSION="18"

# Vérifie si un paramètre est passé au script
if [ "$#" -eq 1 ]; then
    # Affecte le paramètre à la variable d'environnement CURRENT_GIT_TAG
    CURRENT_GIT_TAG=$1
else
    # Affecte le résultat de `git describe --tags` à CURRENT_GIT_TAG
    CURRENT_GIT_TAG=$(git describe --tags)
fi

BRANCH_NAME=$(git branch --show-current)
read -p "Enter branch (default=$BRANCH_NAME) ? " a_branch
if [ -n "$a_branch" ]; then
    BRANCH_NAME=$a_branch
#else
#    BRANCH_NAME="13.0"
fi

PROGRESS_OPT="auto"
read -p "Enter PROGRESS_OPT (eg. 'plain' default=$PROGRESS_OPT) ? " a_progress_opt
if [ -n "$a_progress_opt" ]; then
    PROGRESS_OPT=$a_progress_opt
fi

NO_CACHE_OPT=""
read -p "Disable cache with '--no-cache' (default=No) ? " a_nocache_opt
if [ -n "$a_nocache_opt" ]; then
    NO_CACHE_OPT="--no-cache"
fi

PUSH_IMAGE="No"
read -p "Push image to remote (default=No) ? " a_push_image
if [ -n "$a_push_image" ]; then
    PUSH_IMAGE="Yes"
fi

if [ -n "$CURRENT_GIT_TAG" ]; then 
    NORMALIZED_VERSION=$(py3x/bin/python bin/normalize_version.py $CURRENT_GIT_TAG)
else
    NORMALIZED_VERSION=""
fi

echo "Sunray Server Ver. : ${SUNRAYSRVR_MAIN_VERSION}"
echo "Current Dir.       : $(pwd)"
echo "Current Tag        : ${CURRENT_GIT_TAG}"
echo "Branch.            : ${BRANCH_NAME}"
echo "Progress option    : ${PROGRESS_OPT}"
echo "No Cache option    : ${NO_CACHE_OPT}"
echo "Push image         : ${PUSH_IMAGE}"


CI_COMMIT_REF_NAME=$BRANCH_NAME
echo "docker build --build-arg MPY_REPO_GIT_TOKEN=$MPY_REPO_GIT_TOKEN --build-arg MPY_REPO_GIT_TOKEN_URL_AUTH=$MPY_REPO_GIT_TOKEN_URL_AUTH --build-arg BRANCH_NAME=$CI_COMMIT_REF_NAME \
 --build-arg IKB_ODOO_ADMIN_PASSWORD=$IKB_ODOO_ADMIN_PASSWORD --pull $NO_CACHE_OPT --progress=$PROGRESS_OPT \
 --rm -f "./Dockerfile" -t sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest . "

read -p "Press [Enter] key to start build or CTRL-C to abort..."

docker build \
     --build-arg MPY_REPO_GIT_TOKEN=$MPY_REPO_GIT_TOKEN \
     --build-arg MPY_REPO_GIT_TOKEN_URL_AUTH=$MPY_REPO_GIT_TOKEN_URL_AUTH \
     --build-arg BRANCH_NAME=$CI_COMMIT_REF_NAME \
     --build-arg IKB_ODOO_ADMIN_PASSWORD=$IKB_ODOO_ADMIN_PASSWORD \
     --pull \
     $NO_CACHE_OPT  \
     --progress=$PROGRESS_OPT \
     --rm -f "./Dockerfile" -t sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest . 


# docker va produire une image en local
# qu'il faut tagger pour pouvoir la pousser dans la registry.
# Les lignes vont pousser l'image
docker tag sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest registry.gitlab.com/cmorisse/inouk-sunray-server/sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest 
if [ "$PUSH_IMAGE" == "Yes" ]; then
    echo "docker push registry.gitlab.com/cmorisse/inouk-sunray-server/sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest"
    docker push registry.gitlab.com/cmorisse/inouk-sunray-server/sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest
    sleep 10s
fi

if [ -n "$CURRENT_GIT_TAG" ]; then
    docker tag sunray-srvr$SUNRAYSRVR_MAIN_VERSION:latest registry.gitlab.com/cmorisse/inouk-sunray-server/sunray-srvr$SUNRAYSRVR_MAIN_VERSION:$CURRENT_GIT_TAG 
    if [ "$PUSH_IMAGE" == "Yes" ]; then
        docker push registry.gitlab.com/cmorisse/inouk-sunray-server/sunray-srvr$SUNRAYSRVR_MAIN_VERSION:$CURRENT_GIT_TAG
    fi
else
    echo "CURRENT_GIT_TAG is undefined. Nothing to push in repository."
fi

echo "Use:"
#echo "docker run -e MPY_REPO_GIT_TOKEN="${MPY_REPO_GIT_TOKEN}" -e IKB_ODOO_ADMIN_PASSWORD="choose" -e IKB_VENV_OPTIONS="--system-site-packages" -e IKB_ODOO_CONFIG_DO_NOT_GENERATE="False" -it mpy13c /bin/bash"
echo "  docker run -e MPY_REPO_GIT_TOKEN="\$MPY_REPO_GIT_TOKEN" -e IKB_ODOO_ADMIN_PASSWORD="choose" -it sunray-srvr$SUNRAYSRVR_MAIN_VERSION /bin/bash"
