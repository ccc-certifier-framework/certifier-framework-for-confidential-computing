#pragma once
#ifndef MPL_DEMO_LOAD_MESH_HPP
#define MPL_DEMO_LOAD_MESH_HPP

#include <jilog.hpp>
#include <Eigen/Dense>
#include <assimp/Importer.hpp>
#include <assimp/postprocess.h>
#include <assimp/scene.h>
#include <fcl/geometry/bvh/BVH_model.h>
#include <fcl/narrowphase/collision.h>
// #include <bump/bvh_mesh.hpp>

#include <fstream>      // std::ifstream
namespace mpl::demo {

    template <typename Scalar>
    auto mapToEigen(const aiMatrix4x4t<Scalar>& m) {
        using EigenType = const Eigen::Matrix<Scalar, 4, 4, Eigen::RowMajor>;
        static_assert(sizeof(EigenType) == sizeof(m));
        return Eigen::Map<EigenType>(&m.a1);
    }

    template <typename Scalar>
    auto mapToEigen(const aiVector3t<Scalar>& v) {
        using EigenType = const Eigen::Matrix<Scalar, 3, 1>;
        static_assert(sizeof(EigenType) == sizeof(v));
        return Eigen::Map<const EigenType>(&v.x);
    }

    template <typename Scalar, typename Fn, int mode>
    std::size_t visitVertices(
        const aiScene* scene, const aiNode *node,
        Eigen::Transform<Scalar, 3, mode> transform,
        Fn&& visitor)
    {
        std::size_t count = 0;
        transform *= mapToEigen(node->mTransformation).template cast<Scalar>();
        for (unsigned i=0 ; i < node->mNumMeshes ; ++i) {
            const aiMesh *mesh = scene->mMeshes[node->mMeshes[i]];
            count += mesh->mNumVertices;
            for (unsigned j=0 ; j < mesh->mNumVertices ; ++j)
                visitor(transform * mapToEigen(mesh->mVertices[j]).template cast<Scalar>());
        }
        for (unsigned i=0 ; i < node->mNumChildren ; ++i)
            count += visitVertices(scene, node->mChildren[i], transform, std::forward<Fn>(visitor));
        return count;
    }


    template <typename Scalar, typename Fn, int mode>
    static std::size_t visitTriangles(
        const aiScene *scene, const aiNode *node,
        Eigen::Transform<Scalar, 3, mode> transform,
        Fn&& visitor)
    {
        std::size_t count = 0;
        using Vec3 = Eigen::Matrix<Scalar, 3, 1>;

        JI_LOG(INFO) << "name='" << node->mName.C_Str() << "', M=" << mapToEigen(node->mTransformation);
        transform *= mapToEigen(node->mTransformation).template cast<Scalar>();
        for (unsigned i=0 ; i<node->mNumMeshes ; ++i) {
            const aiMesh *mesh = scene->mMeshes[node->mMeshes[i]];
            for (unsigned j=0 ; j<mesh->mNumFaces ; ++j) {
                const aiFace& face = mesh->mFaces[j];
                if (face.mNumIndices < 3)
                    continue;
            
                // Support trangular decomposition by fanning out
                // around vertex 0.  The indexing follows as:
                //
                //   0---1   0 1 2
                //  /|\ /    0 2 3
                // 4-3-2     0 3 4
                //
                Vec3 v0 = transform * mapToEigen(mesh->mVertices[face.mIndices[0]]).template cast<Scalar>();
                Vec3 v1 = transform * mapToEigen(mesh->mVertices[face.mIndices[1]]).template cast<Scalar>();
                for (unsigned k=2 ; k<face.mNumIndices ; ++k) {
                    Vec3 v2 = transform * mapToEigen(mesh->mVertices[face.mIndices[k]]).template cast<Scalar>();
                    visitor(v0, v1, v2);
                    v1 = v2;
                }
                count += face.mNumIndices - 2;
            }
        }
        for (unsigned i=0 ; i<node->mNumChildren ; ++i)
            count += visitTriangles(scene, node->mChildren[i], transform, std::forward<Fn>(visitor));
    
        return count;
    }

    // template <class Mesh>
    // std::shared_ptr<Mesh> loadMesh(const std::string& name, bool shiftToCenter) {
    //     using S = typename Mesh::S;
    //     using Transform = Eigen::Transform<S, 3, Eigen::Isometry>;
    //     using Vec3 = Eigen::Matrix<S, 3, 1>;

    //     JI_LOG(INFO) << "Loading mesh \"" << name << "\"";
    
    //     std::shared_ptr<Mesh> model = std::make_shared<Mesh>();

    //     Assimp::Importer importer;
    
    //     static constexpr auto readOpts =
    //         aiProcess_Triangulate | aiProcess_JoinIdenticalVertices |
    //         aiProcess_SortByPType | aiProcess_OptimizeGraph | aiProcess_OptimizeMeshes;

    //     const aiScene *scene = importer.ReadFile(name, readOpts);
    //     if (scene == nullptr)
    //         throw std::invalid_argument("could not load mesh file '" + name + "'");

    //     if (!scene->HasMeshes())
    //         throw std::invalid_argument("mesh file '" + name + "' does not contain meshes");
    
    //     // TODO: scene::inferBounds(bounds, vertices, factor_, add_);
    
    //     Transform rootTransform = Transform::Identity();

    //     if (shiftToCenter) {
    //         Vec3 center = Vec3::Zero();
    //         std::size_t nVertices = visitVertices(
    //             scene,
    //             scene->mRootNode,
    //             rootTransform,
    //             [&] (const Vec3& v) { center += v; });
    //         center /= nVertices;
    //         rootTransform *= Eigen::Translation<S, 3>(-center);
    //         JI_LOG(INFO) << "shifted mesh to center: " << center;
    //     }

    //     model->beginModel();
    //     std::size_t nTris = visitTriangles(
    //         scene,
    //         scene->mRootNode,
    //         rootTransform,
    //         [&] (const Vec3& a, const Vec3& b, const Vec3& c) {
    //             model->addTriangle(a, b, c);
    //         });
    //     model->endModel();
    //     model->computeLocalAABB();

    //     return model;
    // };

    void extractTriangles(const aiScene *scene, const aiNode *node, aiMatrix4x4 transform,
                          std::vector<aiVector3D> &triangles)
    {
        transform *= node->mTransformation;
        for (unsigned int i = 0 ; i < node->mNumMeshes; ++i)
        {
            const aiMesh* a = scene->mMeshes[node->mMeshes[i]];
            for (unsigned int i = 0 ; i < a->mNumFaces ; ++i)
                if (a->mFaces[i].mNumIndices == 3)
                {
                    triangles.push_back(transform * a->mVertices[a->mFaces[i].mIndices[0]]);
                    triangles.push_back(transform * a->mVertices[a->mFaces[i].mIndices[1]]);
                    triangles.push_back(transform * a->mVertices[a->mFaces[i].mIndices[2]]);
                }
        }
        
        for (unsigned int n = 0; n < node->mNumChildren; ++n)
            extractTriangles(scene, node->mChildren[n], transform, triangles);
    }
    
    void extractVertices(const aiScene *scene, const aiNode *node, aiMatrix4x4 transform,
                            std::vector<aiVector3D> &vertices)
    {
        transform *= node->mTransformation;
        for (unsigned int i = 0 ; i < node->mNumMeshes; ++i) {
            const aiMesh* a = scene->mMeshes[node->mMeshes[i]];
            for (unsigned int i = 0 ; i < a->mNumVertices ; ++i)
                vertices.push_back(transform * a->mVertices[i]);
        }
        
        for (unsigned int n = 0; n < node->mNumChildren; ++n)
            extractVertices(scene, node->mChildren[n], transform, vertices);
    }

    // template <class Mesh>
    // std::shared_ptr<Mesh> loadMesh2(const std::string& name, bool shiftToCenter) {
    //     using S = typename Mesh::S;
        
    //     std::shared_ptr<Mesh> mesh = std::make_shared<Mesh>();

    //     Assimp::Importer importer;
        
    //     const aiScene *aiScene = importer.ReadFile(
    //         name,
    //         aiProcess_GenNormals | aiProcess_Triangulate |
    //         aiProcess_JoinIdenticalVertices | aiProcess_SortByPType | aiProcess_OptimizeGraph);

    //     if (aiScene == nullptr)
    //         throw std::invalid_argument("unable to load: " + name);
        
    //     if (!aiScene->HasMeshes())
    //         throw std::invalid_argument("No mesh found in " + name);

    //     std::vector<aiVector3D> vertices;
    //     extractVertices(aiScene, aiScene->mRootNode, aiMatrix4x4(), vertices);
    //     aiVector3D center;
    //     center.Set(0, 0, 0);
    //     for (auto& v : vertices)
    //         center += v;
    //     center /= vertices.size();

    //     std::vector<fcl::Triangle> triangles;
    //     std::vector<fcl::Vector3<S>> pts;
    //     vertices.clear();
    //     extractTriangles(aiScene, aiScene->mRootNode, aiMatrix4x4(), vertices);
    //     assert(vertices.size() % 3 == 0);

    //     if (shiftToCenter) {
    //         for (auto& j : vertices)
    //             j -= center;
    //     }

    //     for (auto& j : vertices)
    //         pts.emplace_back(j[0], j[1], j[2]);
        
    //     for (unsigned j = 0 ; j<vertices.size() ; j += 3)
    //         triangles.emplace_back(j, j+1, j+2);

    //     mesh->beginModel();
    //     mesh->addSubModel(pts, triangles);
    //     mesh->endModel();
    //     mesh->computeLocalAABB();
    //     return mesh;
    // }

    template <class Mesh>
    struct MeshLoad;

    template <class S>
    struct MeshLoad<fcl::BVHModel<fcl::OBBRSS<S>>> {
        using Mesh = fcl::BVHModel<fcl::OBBRSS<S>>;
        static Mesh load(const std::string& name, bool shiftToCenter, bool identityRootTransform) {
            using Transform = Eigen::Transform<S, 3, Eigen::Isometry>;
            using Vec3 = Eigen::Matrix<S, 3, 1>;

            JI_LOG(INFO) << "Loading mesh \"" << name << "\"";
            
            Mesh model;

            Assimp::Importer importer;
            
            static constexpr auto readOpts =
                aiProcess_Triangulate | aiProcess_JoinIdenticalVertices |
                aiProcess_SortByPType | aiProcess_OptimizeGraph | aiProcess_OptimizeMeshes;
            

            std::ifstream infile(name);
            printf("file exist: %d", infile.good());
            std::ostringstream buf; 
            buf << infile.rdbuf(); 
            printf("dataset size is %lu", buf.str().size());
        
            //const aiScene *scene = importer.ReadFile(name, readOpts);
            // const aiScene *scene = importer.ReadFileFromMemory(buf.str().c_str(), buf.str().size(), readOpts);
            const aiScene *scene = importer.ReadFileFromMemory(buf.str().c_str(), buf.str().size(), readOpts);
            if (scene == nullptr){
                JI_LOG(ERROR) << "could not load mesh file '" + name + "'\nOffocial error message: ";
                JI_LOG(ERROR) << importer.GetErrorString();
                throw std::invalid_argument("could not load mesh file '" + name + "'");
            }
            
            if (!scene->HasMeshes()){
                JI_LOG(ERROR) << "mesh file '" + name + "' does not contain meshes";
                throw std::invalid_argument("mesh file '" + name + "' does not contain meshes");
            }

            if (identityRootTransform)
                scene->mRootNode->mTransformation = aiMatrix4x4();
            
            // TODO: scene::inferBounds(bounds, vertices, factor_, add_);
            
            Transform rootTransform = Transform::Identity();
            
            if (shiftToCenter) {
                Vec3 center = Vec3::Zero();
                std::size_t nVertices = visitVertices(
                    scene,
                    scene->mRootNode,
                    Transform::Identity(),
                    [&] (const Vec3& v) { center += v; });
                center /= nVertices;
                rootTransform *= Eigen::Translation<S, 3>(-center);
                JI_LOG(INFO) << "shifted mesh to center: " << center;
            }
            
            model.beginModel();
            std::size_t nTris = visitTriangles(
                scene,
                scene->mRootNode,
                rootTransform,
                [&] (const Vec3& a, const Vec3& b, const Vec3& c) {
                    model.addTriangle(a, b, c);
                });
            model.endModel();
            model.computeLocalAABB();

            JI_LOG(INFO) << "Loaded mesh \"" << name << "\" AABB={c=" << model.aabb_center
                         << ", r=" << model.aabb_radius
                         << ", min=" << model.aabb_local.min_
                         << ", max=" << model.aabb_local.max_ << "}";

            return model;
        }
    };
// #if 0
//     template <class I, class S>
//     struct MeshLoad<bump::BVHMesh<bump::Triangle<I>, bump::OBB<S>>> {
//         using Mesh = bump::BVHMesh<bump::Triangle<I>, bump::OBB<S>>;
//         static Mesh load(const std::string& name, bool shiftToCenter) {
//             using Transform = Eigen::Transform<S, 3, Eigen::AffineCompact>;
//             using Vec3 = Eigen::Matrix<S, 3, 1>;
//             Assimp::Importer importer;

//             static constexpr auto readOpts =
//                 aiProcess_Triangulate | aiProcess_JoinIdenticalVertices |
//                 aiProcess_SortByPType | aiProcess_OptimizeGraph | aiProcess_OptimizeMeshes;

//             const aiScene *scene = importer.ReadFile(name, readOpts);

//             if (scene == nullptr)
//                 throw std::invalid_argument("could not load mesh file '" + name + "'");
            
//             if (!scene->HasMeshes())
//                 throw std::invalid_argument("mesh file '" + name + "' does not contain meshes");
            
//             Transform rootTransform = Transform::Identity();
            
//             if (shiftToCenter) {
//                 Vec3 center = Vec3::Zero();
//                 std::size_t nVertices = visitVertices(
//                     scene,
//                     scene->mRootNode,
//                     Transform::Identity(),
//                     [&] (const Vec3& v) { center += v; });
//                 center /= nVertices;
//                 rootTransform *= Eigen::Translation<S, 3>(-center);
//                 JI_LOG(INFO) << "shifted mesh to center: " << center;
//             }
            
//             std::vector<Vec3> vertices;
//             std::vector<bump::Triangle<I>> triangles;
            
//             std::size_t nTris = visitTriangles(
//                 scene,
//                 scene->mRootNode,
//                 rootTransform,
//                 [&] (const Vec3& a, const Vec3& b, const Vec3& c) {
//                     I i = vertices.size();
//                     vertices.push_back(a);
//                     vertices.push_back(b);
//                     vertices.push_back(c);
                    
//                     triangles.emplace_back(i, i+1, i+2);
//                 });
            
//             return bump::BVHMesh<bump::Triangle<int>>(vertices, triangles);
//         }
//     };
// #endif

    
}

#endif
